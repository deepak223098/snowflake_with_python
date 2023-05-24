from utilities.utility import snowflake_database_connection as db
import pandas as pd
import os

engine, conn = db(db="bulkdb", schema= "test")

print("engine info", engine.engine)

# CSV file path
csv_file_path = r'abc_1.csv'
table = "abc_1"
file_path = os.path.abspath(csv_file_path)
# Cursor
cursor = conn.cursor()
cursor.execute("create or replace table abc_1(id number, name varchar, company varchar);")

stage_name = 'trayaksh'
# Create stage
create_stage_command = f"CREATE OR REPLACE STAGE {stage_name}"
cursor.execute(create_stage_command)

# Put the CSV file into the stage
# put_command = f"PUT 'file://{csv_file_path}' @{stage_name}"
put_command = f"put file://{csv_file_path} @{stage_name}"
cursor.execute(put_command)

# file format
create_format_command = f"CREATE OR REPLACE FILE FORMAT csv_format TYPE = 'CSV' FIELD_DELIMITER = ',' SKIP_HEADER = 1;"
cursor.execute(create_format_command)
# copy_command = f"COPY INTO {table} FROM @{stage_name} FILE_FORMAT = (FORMAT_NAME = 'csv_format')"

# Bulk load command
# copy_command = f"COPY INTO {table} FROM '{csv_file_path}'"
copy_command = f"COPY INTO {table} FROM @{stage_name} FILE_FORMAT = (FORMAT_NAME = 'csv_format')"


# Execute the bulk load command
cursor.execute(copy_command)

# Commit the transaction
conn.commit()

# Close the cursor and connection
cursor.close()
conn.close()
