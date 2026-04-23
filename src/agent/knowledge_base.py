from langchain_chroma import Chroma
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_core.documents import Document
import os

from src.data.mitre_knowledge import MITRE_TECHNIQUES

# Where ChromaDB saves its data on your disk
CHROMA_PATH = "src/data/chroma_db"


def build_knowledge_base():
    """
    Convert MITRE ATT&CK techniques into vector embeddings
    and store them in ChromaDB.
    Only needs to run once — database persists on disk.
    """
    print("Building MITRE ATT&CK knowledge base...")
    print("This converts text into vectors so AI can search by meaning...")

    # Convert each technique into a Document object
    # We combine all fields into one searchable text block
    documents = []
    for technique in MITRE_TECHNIQUES:
        content = f"""
Technique ID: {technique['id']}
Name: {technique['name']}
Tactic: {technique['tactic']}
Description: {technique['description']}
Threat Groups: {technique['threat_groups']}
Indicators: {technique['indicators']}
Next Likely Techniques: {technique['next_techniques']}
Mitigation: {technique['mitigation']}
        """.strip()

        doc = Document(
            page_content=content,
            metadata={
                "id": technique["id"],
                "name": technique["name"],
                "tactic": technique["tactic"]
            }
        )
        documents.append(doc)

    # Create embeddings — converts text to numbers
    # all-MiniLM-L6-v2 is free, fast, and runs locally on your machine
    embeddings = SentenceTransformerEmbeddings(
        model_name="all-MiniLM-L6-v2"
    )

    # Store documents in ChromaDB
    db = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=CHROMA_PATH
    )

    print(f"Knowledge base built — {len(documents)} MITRE techniques stored")
    print(f"Saved to: {CHROMA_PATH}")
    return db


def load_knowledge_base():
    """
    Load the existing knowledge base from disk.
    Much faster than rebuilding every time.
    """
    embeddings = SentenceTransformerEmbeddings(
        model_name="all-MiniLM-L6-v2"
    )

    db = Chroma(
        persist_directory=CHROMA_PATH,
        embedding_function=embeddings
    )

    return db


def search_mitre(query: str, k: int = 2) -> str:
    """
    Search the knowledge base for techniques matching the query.
    k = number of results to return.
    Uses semantic search — finds meaning, not just keywords.
    """
    # Build if it doesn't exist yet
    if not os.path.exists(CHROMA_PATH):
        build_knowledge_base()

    db = load_knowledge_base()

    # Semantic search — finds techniques similar in meaning to query
    results = db.similarity_search(query, k=k)

    if not results:
        return "No matching MITRE techniques found"

    output = []
    for doc in results:
        output.append(doc.page_content)

    return "\n\n---\n\n".join(output)


if __name__ == "__main__":
    # Run this file directly to build the database
    build_knowledge_base()
    print("\nTesting search...")
    result = search_mitre("SSH brute force login attempts")
    print(result)