import os
import glob
from time import time
import uuid
import requests
from qdrant_client import QdrantClient, models
from jproperties import Properties
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.docstore.document import Document
import markdown
from PyPDF2 import PdfReader
from google import genai
from ollama import Client as OllamaClient
# Load configs
configs = Properties()
with open('app_config.properties', 'rb') as config_file:
    configs.load(config_file)

QDRANT_URL = configs.get("QDRANT_URL").data
QDRANT_API_KEY = configs.get("QDRANT_API_KEY").data
QDRANT_COLLECTION_NAME = configs.get("QDRANT_COLLECTION_NAME").data
GEMINI_API_KEY = configs.get("GEMINI_API_KEY").data
GEMINI_EMBEDDING_URL = configs.get("GEMINI_API_URL").data
DATA_FOLDER = configs.get("DATA_FOLDER").data if configs.get("DATA_FOLDER") else "data"

# Qdrant client
qdrant_client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)
client = genai.Client(api_key=GEMINI_API_KEY)

# Delete existing collection (optional)
try:
    qdrant_client.delete_collection(collection_name=QDRANT_COLLECTION_NAME)
    print("Existing collection deleted.")
except Exception as e:
    print(f"Error deleting collection: {e}")

# Create collection if not exists
try:
    qdrant_client.create_collection(
        collection_name=QDRANT_COLLECTION_NAME,
        vectors_config=models.VectorParams(
            size=4096,  # gemini-embedding-001 output size
            distance=models.Distance.COSINE,
        ),
    )
    print("Collection created.")
except Exception as e:
    if "already exists" in str(e):
        print("Collection already exists.")
    else:
        print(f"Error creating collection: {e}")

def extract_markdown_content(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()
    # Optionally strip markdown formatting
    html = markdown.markdown(text)
    # Remove HTML tags for plain text
    return ''.join(html.splitlines())

def extract_pdf_content(filepath):
    reader = PdfReader(filepath)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

Ollama_Client = OllamaClient(host="http://localhost:11434")

def get_embedding(text, model="llama3"):
    return Ollama_Client.embeddings( prompt=text,model=model).embedding
# def get_embedding(text):
#     response = client.models.embed_content(
#         model="gemini-embedding-001",
#         contents=text
#     )
#     return response.embeddings[0].values

def main():
    # Find markdown and pdf files
    md_files = glob.glob(os.path.join(DATA_FOLDER, "*.md"))
    pdf_files = glob.glob(os.path.join(DATA_FOLDER, "*.pdf"))
    print(f"Found {len(md_files)} markdown and {len(pdf_files)} pdf files.")

    documents = []
    # Markdown
    for filepath in md_files:
        content = extract_markdown_content(filepath)
        doc = Document(page_content=content, metadata={"source": filepath, "type": "markdown"})
        documents.append(doc)
    # PDF
    for filepath in pdf_files:
        content = extract_pdf_content(filepath)
        doc = Document(page_content=content, metadata={"source": filepath, "type": "pdf"})
        documents.append(doc)

    # Split documents
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=2000, chunk_overlap=200)
    texts = text_splitter.split_documents(documents)
    print(f"Split into {len(texts)} chunks.")

    # Batch upload
    batch_size = 2
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        points = []
        for doc in batch:
            try:
                embedding = get_embedding(doc.page_content)
                point_id = str(uuid.uuid4())
                point = models.PointStruct(
                    id=point_id,
                    vector=embedding,
                    payload={
                        "content": doc.page_content,
                        "source": doc.metadata.get("source", ""),
                        "type": doc.metadata.get("type", ""),
                    }
                )
                points.append(point)
            except Exception as e:
                print(f"Error embedding doc: {e}")
        if points:
            qdrant_client.upsert(
                collection_name=QDRANT_COLLECTION_NAME,
                points=points
            )
            print(f"Uploaded {len(points)} points to Qdrant.")

if __name__ == "__main__":
    main()