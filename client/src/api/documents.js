import apiClient from './client';

/**
 * Retrieves all accessible documents (owned, granted, or all if admin).
 *
 * @returns {Promise<Array>} List of document metadata objects
 */
export async function fetchDocuments() {
  const response = await apiClient('/documents');
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Failed to fetch documents.');
  }
  const data = await response.json();
  return data.documents || [];
}

/**
 * Uploads a document via multipart FormData.
 * File buffer is encrypted in-memory with AES-256-GCM before storage persistence.
 *
 * @param {FormData} formData - Multipart data containing `document`, `title`, and optional `category`
 * @returns {Promise<Object>} The uploaded document metadata
 */
export async function uploadDocument(formData) {
  const response = await apiClient('/documents/upload', {
    method: 'POST',
    body: formData
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Upload failed.');
  }

  const data = await response.json();
  return data.document;
}

/**
 * Downloads and decrypts an encrypted document stream from the PEP endpoint.
 * Triggers a browser download using a temporary object URL.
 *
 * @param {string} id - Document UUID
 * @param {string} [fileName] - Expected file name for download
 */
export async function downloadDocument(id, fileName = 'document.bin') {
  const response = await apiClient(`/documents/${id}/download`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Download denied by PEP policy.');
  }

  // Extract filename from Content-Disposition header if available
  let resolvedFileName = fileName;
  const disposition = response.headers.get('Content-Disposition');
  if (disposition && disposition.includes('filename=')) {
    const match = disposition.match(/filename="?([^"]+)"?/);
    if (match && match[1]) {
      try {
        resolvedFileName = decodeURIComponent(match[1]);
      } catch {
        resolvedFileName = match[1];
      }
    }
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = downloadUrl;
  anchor.download = resolvedFileName;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  // Revoke object URL after a brief timeout to free memory
  setTimeout(() => {
    window.URL.revokeObjectURL(downloadUrl);
  }, 1000);
}

/**
 * Deletes a document from the vault (Owner or Admin only).
 *
 * @param {string} id - Document UUID
 * @returns {Promise<Object>}
 */
export async function deleteDocument(id) {
  const response = await apiClient(`/documents/${id}`, {
    method: 'DELETE'
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || errorData.message || 'Failed to delete document.');
  }

  return await response.json();
}
