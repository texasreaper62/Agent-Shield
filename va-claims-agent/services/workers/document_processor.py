"""
Document Processing Worker

Processes documents from the queue:
1. Downloads from blob storage
2. Runs OCR using Azure Document Intelligence
3. Classifies the document
4. Chunks the text
5. Generates embeddings
6. Stores in database
"""
import asyncio
import json
from datetime import datetime
from uuid import UUID
from azure.ai.formrecognizer.aio import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select
import structlog

# Import from API app
import sys
sys.path.append('../apps/api')

from config import settings
from models.database import Base
from models.document import Document, DocumentChunk, DocumentStatus
from services.storage import download_blob
from services.embeddings import get_embedding
from agents.document_classifier import DocumentClassifierAgent

logger = structlog.get_logger()

# Database connection
engine = create_async_engine(settings.DATABASE_URL)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class DocumentProcessor:
    """Processes uploaded documents."""

    def __init__(self):
        self.classifier = DocumentClassifierAgent()
        self.ocr_client = DocumentAnalysisClient(
            endpoint=settings.AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT,
            credential=AzureKeyCredential(settings.AZURE_DOCUMENT_INTELLIGENCE_KEY)
        )

    async def process_document(self, message: dict) -> None:
        """
        Process a single document.

        Args:
            message: Queue message with document_id and storage_path
        """
        document_id = message['document_id']
        storage_path = message['storage_path']

        logger.info("Processing document", document_id=document_id)

        async with async_session() as session:
            try:
                # Get document record
                result = await session.execute(
                    select(Document).where(Document.id == UUID(document_id))
                )
                document = result.scalar_one_or_none()
                if not document:
                    logger.error("Document not found", document_id=document_id)
                    return

                # Update status
                document.status = DocumentStatus.PROCESSING
                await session.commit()

                # Download file
                file_data = await download_blob(storage_path)

                # Run OCR
                ocr_result = await self._run_ocr(file_data, document.mime_type)
                document.ocr_text = ocr_result['text']
                document.ocr_confidence = ocr_result['confidence']
                document.page_count = ocr_result['page_count']
                document.status = DocumentStatus.OCR_COMPLETE
                await session.commit()

                # Classify document
                classification = await self.classifier.process(
                    document_id=document_id,
                    filename=document.original_filename,
                    content_preview=document.ocr_text[:2000] if document.ocr_text else "",
                    mime_type=document.mime_type
                )
                document.document_type = classification['document_type']
                document.confidence_score = classification['confidence']
                document.status = DocumentStatus.CLASSIFIED
                await session.commit()

                # Chunk text
                chunks = self._chunk_text(document.ocr_text, document_id)

                # Generate embeddings and store chunks
                for chunk_data in chunks:
                    embedding = await get_embedding(chunk_data['content'])
                    chunk = DocumentChunk(
                        document_id=UUID(document_id),
                        content=chunk_data['content'],
                        chunk_index=chunk_data['index'],
                        page_number=chunk_data.get('page'),
                        start_char=chunk_data.get('start_char'),
                        end_char=chunk_data.get('end_char'),
                        embedding=embedding,
                        token_count=len(chunk_data['content'].split())
                    )
                    session.add(chunk)

                document.status = DocumentStatus.EMBEDDED
                document.processed_at = datetime.utcnow()
                await session.commit()

                logger.info(
                    "Document processed successfully",
                    document_id=document_id,
                    chunks=len(chunks)
                )

            except Exception as e:
                logger.error("Document processing failed", error=str(e), document_id=document_id)
                document.status = DocumentStatus.FAILED
                document.error_message = str(e)
                await session.commit()
                raise

    async def _run_ocr(self, file_data: bytes, mime_type: str) -> dict:
        """Run OCR on document."""
        try:
            async with self.ocr_client:
                poller = await self.ocr_client.begin_analyze_document(
                    "prebuilt-document",
                    file_data
                )
                result = await poller.result()

            # Extract text from all pages
            full_text = ""
            for page in result.pages:
                for line in page.lines:
                    full_text += line.content + "\n"
                full_text += "\n---PAGE BREAK---\n"

            # Calculate average confidence
            confidences = []
            for page in result.pages:
                for word in page.words:
                    if word.confidence:
                        confidences.append(word.confidence)

            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            return {
                'text': full_text,
                'confidence': avg_confidence,
                'page_count': len(result.pages)
            }

        except Exception as e:
            logger.error("OCR failed", error=str(e))
            # Return empty result on failure
            return {
                'text': '',
                'confidence': 0.0,
                'page_count': 0
            }

    def _chunk_text(
        self,
        text: str,
        document_id: str,
        chunk_size: int = 1000,
        overlap: int = 200
    ) -> list:
        """
        Split text into overlapping chunks for embedding.

        Args:
            text: Full document text
            document_id: Document ID
            chunk_size: Target chunk size in characters
            overlap: Overlap between chunks

        Returns:
            List of chunk dictionaries
        """
        if not text:
            return []

        chunks = []
        start = 0
        index = 0

        while start < len(text):
            end = start + chunk_size

            # Try to break at sentence boundary
            if end < len(text):
                # Look for sentence ending
                for sep in ['. ', '.\n', '! ', '? ']:
                    last_sep = text[start:end].rfind(sep)
                    if last_sep > chunk_size // 2:
                        end = start + last_sep + len(sep)
                        break

            chunk_text = text[start:end].strip()

            if chunk_text:
                # Detect page number from PAGE BREAK markers
                page = None
                page_breaks_before = text[:start].count('---PAGE BREAK---')
                if page_breaks_before >= 0:
                    page = page_breaks_before + 1

                chunks.append({
                    'content': chunk_text.replace('---PAGE BREAK---', ''),
                    'index': index,
                    'page': page,
                    'start_char': start,
                    'end_char': end
                })
                index += 1

            start = end - overlap

        return chunks


async def process_queue():
    """Main queue processing loop."""
    from azure.servicebus.aio import ServiceBusClient

    processor = DocumentProcessor()

    async with ServiceBusClient.from_connection_string(
        settings.AZURE_SERVICE_BUS_CONNECTION_STRING
    ) as client:
        receiver = client.get_queue_receiver(
            queue_name=settings.AZURE_SERVICE_BUS_QUEUE_DOCUMENTS
        )

        async with receiver:
            logger.info("Document processor started, listening for messages...")

            while True:
                messages = await receiver.receive_messages(
                    max_message_count=10,
                    max_wait_time=30
                )

                for message in messages:
                    try:
                        data = json.loads(str(message))
                        await processor.process_document(data)
                        await receiver.complete_message(message)
                    except Exception as e:
                        logger.error("Failed to process message", error=str(e))
                        await receiver.dead_letter_message(message, reason=str(e))


if __name__ == "__main__":
    asyncio.run(process_queue())
