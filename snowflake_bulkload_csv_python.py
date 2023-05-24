from utilities.utility import snowflake_database_connection as db
import pandas as pd

engine, conn = db(db="bulkdb", schema= "test")

# read the file from disk
df = pd.read_csv("yourfilename.csv")
# push the dataframe into snowflake table using to_sql module
# to calcualte the chunksize get the number = int(16000/len(df.columns))
df.to_sql(name="youtablename", con=engine,
                           if_exists=savetype, index=False, chunksize=2600,
                           method='multi')