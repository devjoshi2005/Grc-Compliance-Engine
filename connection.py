import pyodbc,os 


conn_str = f'DRIVER={{ODBC Driver 18 for SQL Server}};SERVER={os.getenv("server")};DATABASE=master;UID={os.getenv("username")};PWD={os.getenv("password")};Encrypt=yes;TrustServerCertificate=yes;'

try:
    conn = pyodbc.connect(conn_str, autocommit=True) 
    cursor = conn.cursor()
    
    cursor.execute("IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'EMP_DB') CREATE DATABASE EMP_DB")
    print("Database 'EMP_DB' created successfully.")
    
    cursor.execute("USE EMP_DB")
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'EMP_DETAILS')
        CREATE TABLE EMP_DETAILS (
            id INT PRIMARY KEY NOT NULL,
            user_name NVARCHAR(50) NOT NULL,
            dept NVARCHAR(50) NOT NULL
        )
    """)
    cursor.execute("INSERT INTO EMP_DETAILS (id, user_name, dept) VALUES(1, 'John Doe', 'IT'),(2, 'Jane Smith', 'HR')")
    print(" Table created and records inserted.")
    
    conn.close()
except Exception as e:
    print(f" Error: {e}")