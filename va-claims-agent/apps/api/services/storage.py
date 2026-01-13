"""
Azure Blob Storage service for document management.
"""
from datetime import datetime, timedelta
from typing import Optional
from azure.storage.blob.aio import BlobServiceClient
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
import structlog

from config import settings

logger = structlog.get_logger()


def get_blob_service_client() -> BlobServiceClient:
    """Get Azure Blob Service client."""
    connection_string = (
        f"DefaultEndpointsProtocol=https;"
        f"AccountName={settings.AZURE_STORAGE_ACCOUNT};"
        f"AccountKey={settings.AZURE_STORAGE_KEY};"
        f"EndpointSuffix=core.windows.net"
    )
    return BlobServiceClient.from_connection_string(connection_string)


async def upload_to_blob(
    path: str,
    data: bytes,
    content_type: Optional[str] = None,
    container: str = None
) -> str:
    """
    Upload data to Azure Blob Storage.

    Args:
        path: Blob path within container
        data: File data as bytes
        content_type: MIME type of the file
        container: Container name (defaults to uploads)

    Returns:
        Full blob URL
    """
    container = container or settings.AZURE_BLOB_CONTAINER_UPLOADS

    async with get_blob_service_client() as client:
        container_client = client.get_container_client(container)

        # Create container if it doesn't exist
        try:
            await container_client.create_container()
        except Exception:
            pass  # Container already exists

        blob_client = container_client.get_blob_client(path)

        await blob_client.upload_blob(
            data,
            content_settings={"content_type": content_type} if content_type else None,
            overwrite=True,
        )

        logger.info("Blob uploaded", path=path, container=container, size=len(data))

        return blob_client.url


async def download_blob(path: str, container: str = None) -> bytes:
    """
    Download blob data.

    Args:
        path: Blob path within container
        container: Container name

    Returns:
        File data as bytes
    """
    container = container or settings.AZURE_BLOB_CONTAINER_UPLOADS

    async with get_blob_service_client() as client:
        blob_client = client.get_blob_client(container=container, blob=path)
        downloader = await blob_client.download_blob()
        data = await downloader.readall()

        logger.info("Blob downloaded", path=path, size=len(data))

        return data


async def get_blob_url(path: str, container: str = None, expiry_hours: int = 1) -> str:
    """
    Generate a SAS URL for blob access.

    Args:
        path: Blob path within container
        container: Container name
        expiry_hours: Hours until URL expires

    Returns:
        SAS URL for blob access
    """
    container = container or settings.AZURE_BLOB_CONTAINER_UPLOADS

    sas_token = generate_blob_sas(
        account_name=settings.AZURE_STORAGE_ACCOUNT,
        container_name=container,
        blob_name=path,
        account_key=settings.AZURE_STORAGE_KEY,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
    )

    url = (
        f"https://{settings.AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/"
        f"{container}/{path}?{sas_token}"
    )

    logger.debug("SAS URL generated", path=path, expiry_hours=expiry_hours)

    return url


async def delete_blob(path: str, container: str = None) -> None:
    """
    Delete a blob.

    Args:
        path: Blob path within container
        container: Container name
    """
    container = container or settings.AZURE_BLOB_CONTAINER_UPLOADS

    async with get_blob_service_client() as client:
        blob_client = client.get_blob_client(container=container, blob=path)
        await blob_client.delete_blob()

        logger.info("Blob deleted", path=path)


async def list_blobs(prefix: str = "", container: str = None) -> list:
    """
    List blobs with optional prefix.

    Args:
        prefix: Blob name prefix filter
        container: Container name

    Returns:
        List of blob names
    """
    container = container or settings.AZURE_BLOB_CONTAINER_UPLOADS

    async with get_blob_service_client() as client:
        container_client = client.get_container_client(container)
        blobs = []

        async for blob in container_client.list_blobs(name_starts_with=prefix):
            blobs.append({
                "name": blob.name,
                "size": blob.size,
                "last_modified": blob.last_modified,
            })

        return blobs


async def copy_blob(
    source_path: str,
    dest_path: str,
    source_container: str = None,
    dest_container: str = None
) -> str:
    """
    Copy a blob to a new location.

    Args:
        source_path: Source blob path
        dest_path: Destination blob path
        source_container: Source container
        dest_container: Destination container

    Returns:
        Destination blob URL
    """
    source_container = source_container or settings.AZURE_BLOB_CONTAINER_UPLOADS
    dest_container = dest_container or settings.AZURE_BLOB_CONTAINER_PROCESSED

    # Get source URL with SAS
    source_url = await get_blob_url(source_path, source_container)

    async with get_blob_service_client() as client:
        dest_blob = client.get_blob_client(container=dest_container, blob=dest_path)
        await dest_blob.start_copy_from_url(source_url)

        logger.info("Blob copied", source=source_path, dest=dest_path)

        return dest_blob.url
