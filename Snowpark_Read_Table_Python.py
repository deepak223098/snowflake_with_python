from snowflake.snowpark import Session
import snowflake.snowpark as snowpark
from snowflake.snowpark.functions import col
from snowflake.snowpark import Row
import json
with open(r"utilities\db_config.json", "r") as fd:
    cfg = json.loads(fd.read())
    cfg = cfg["DG"]
    cfg = cfg["dev"]

connection_parameters = {
    "account":  cfg["account"],
    "user": cfg["user"],
    "password": cfg["password"],
    "database": "bulkdb",
    "schema": "test",
}
new_session = Session.builder.configs(connection_parameters).create()
# query to read the data from table
query = "select * from abc_1"
# read the data from snowflake table
df = new_session.sql(query)
df.show()