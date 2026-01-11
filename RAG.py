import os
from llama_index.core import VectorStoreIndex,Settings
from llama_index.readers.file import PyMuPDFReader
from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.core import StorageContext
from llama_index.embeddings.openai import OpenAIEmbedding
import chromadb

Settings.embed_model = OpenAIEmbedding(api_key=os.getenv("OPENAI_API_KEY"))

loader = PyMuPDFReader()
docs = []
for file_path in [
    "docs/NIST.SP.800-53r5.pdf",
    "docs/PCI-DSS-v4_0_1.pdf",
    "docs/NIST_ISO_MAPPING.pdf",
    "docs/CIS_AWS_Foundations.pdf",
]:
    print(f"Loading {file_path}")
    docs.extend(loader.load(file_path=file_path))

chroma_client = chromadb.PersistentClient(path="./compliance_db1")
chroma_collection = chroma_client.create_collection("compliance")
vector_store = ChromaVectorStore(chroma_collection=chroma_collection)

storage_context = StorageContext.from_defaults(vector_store=vector_store)

index = VectorStoreIndex.from_documents(
    docs,
    storage_context=storage_context,
    chunk_size=1000,
    chunk_overlap=100,
)

print("Compliance Knowledge Base Created!")   