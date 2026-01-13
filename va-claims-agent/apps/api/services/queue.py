"""
Azure Service Bus queue service for async processing.
"""
import json
from azure.servicebus.aio import ServiceBusClient
from azure.servicebus import ServiceBusMessage
import structlog

from config import settings

logger = structlog.get_logger()


def get_servicebus_client() -> ServiceBusClient:
    """Get Azure Service Bus client."""
    return ServiceBusClient.from_connection_string(
        settings.AZURE_SERVICE_BUS_CONNECTION_STRING
    )


async def send_message(queue_name: str, message: dict) -> None:
    """
    Send a message to a Service Bus queue.

    Args:
        queue_name: Name of the queue
        message: Message data as dictionary
    """
    async with get_servicebus_client() as client:
        sender = client.get_queue_sender(queue_name=queue_name)
        async with sender:
            sb_message = ServiceBusMessage(json.dumps(message))
            await sender.send_messages(sb_message)

            logger.info("Message sent to queue", queue=queue_name, message_keys=list(message.keys()))


async def send_to_processing_queue(message: dict) -> None:
    """
    Send document to processing queue.

    Expected message format:
    {
        "document_id": str,
        "storage_path": str,
        "veteran_id": str,
    }
    """
    await send_message(settings.AZURE_SERVICE_BUS_QUEUE_DOCUMENTS, message)


async def send_to_analysis_queue(message: dict) -> None:
    """
    Send claim to analysis queue.

    Expected message format:
    {
        "claim_id": str,
        "veteran_id": str,
        "conditions": List[str],
    }
    """
    await send_message(settings.AZURE_SERVICE_BUS_QUEUE_CLAIMS, message)


async def send_to_forms_queue(message: dict) -> None:
    """
    Send form generation request to queue.

    Expected message format:
    {
        "form_id": str,
        "claim_id": str,
        "form_number": str,
        "regenerate": bool (optional),
    }
    """
    await send_message(settings.AZURE_SERVICE_BUS_QUEUE_FORMS, message)


async def receive_messages(queue_name: str, max_messages: int = 10, timeout: int = 30):
    """
    Receive messages from a queue.

    Args:
        queue_name: Name of the queue
        max_messages: Maximum messages to receive
        timeout: Timeout in seconds

    Yields:
        Message data as dictionary
    """
    async with get_servicebus_client() as client:
        receiver = client.get_queue_receiver(queue_name=queue_name)
        async with receiver:
            messages = await receiver.receive_messages(
                max_message_count=max_messages,
                max_wait_time=timeout
            )

            for message in messages:
                try:
                    data = json.loads(str(message))
                    yield data, message
                except json.JSONDecodeError:
                    logger.error("Invalid message format", queue=queue_name)
                    await receiver.dead_letter_message(message)


async def complete_message(receiver, message) -> None:
    """Mark message as completed."""
    await receiver.complete_message(message)


async def dead_letter_message(receiver, message, reason: str = None) -> None:
    """Move message to dead letter queue."""
    await receiver.dead_letter_message(
        message,
        reason=reason or "Processing failed"
    )
