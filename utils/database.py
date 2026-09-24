import psycopg2
import os
from dotenv import load_dotenv
load_dotenv()


class DatabaseUtil:

    def __init__(self, db_config):
        self.db_config = db_config
        try:
            self.conn = psycopg2.connect(**db_config)
        except Exception as e:
            self.conn = None
            raise Exception("Database connection failed.") from e

    def schema_details(self, schema_name):
        try:
            connection = self.conn
            cursor = connection.cursor()

            schema_info_context = f"Databse Schema: {schema_name}"
            cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s;", (schema_name,))
            tables_list = cursor.fetchall()

            for table in tables_list:
                table_name = table[0]
                schema_info_context = f"{schema_info_context}\n Table: {table_name}"
                cursor.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = %s;", (table_name,))
                columns_list = cursor.fetchall()

                for column in columns_list:
                    column_name = column[0]
                    data_type = column[1]
                    schema_info_context = f"{schema_info_context}\n  Column_name: {column_name}, Data_type: {data_type}"

                cursor.execute(f"SELECT * from {schema_name}.{table_name} LIMIT 5;")
                sample_data = cursor.fetchall()
                schema_info_context = f"{schema_info_context}\n Sample Data: {sample_data}"
    
        except Exception as e:
            raise Exception("Failed to retrieve schema details.") from e
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
        return schema_info_context


if __name__ == "__main__":
    db_config = {
        "host": os.environ["host"],
        "password": os.environ["password"],
        "port": os.environ["port"],
        "user": os.environ["user"],
        "database": os.environ["database"]
    }
    obj = DatabaseUtil(db_config)
    db_schema = obj.schema_details(schema_name="public")
    with open("schema_details.txt", "w") as f:
        f.write(db_schema)

