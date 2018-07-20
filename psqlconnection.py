import psycopg2
import json

class PSQLConnection(object):

    def __init__(self, app, db):

        self.conn=psycopg2.connect(dbname=db,
                                 host="localhost",
                                 port="5432",
                                 user="postgres",
                                 password="FootBall24!!")

    def query_db(self, query):
        
        
        cur = self.conn.cursor()
        cur.execute(query)

        if query[0:6].lower() == 'select':

            # if select, make result list of dicts
            
            #list_result = [dict(r) for r in cur.fetchall()]
            #cur.close()
            # return the results as a list of dictionaries
            #return list_result
            r = [dict((cur.description[i][0], value) \
                for i, value in enumerate(row)) for row in cur.fetchall()]
            cur.close()
            
            #return json.dumps((r[0] if r else None) if one else r)
            return r

        elif query[0:6].lower() == 'insert':

            # if insert, return id
            
            
            self.conn.commit()
            cur.close()
            
            return result
            
        else:

            # if update/delete commit and return nothing
            
            self.conn.commit()
            
            cur.close()
        

def PSQLConnector(app, db):
    return PSQLConnection(app, db)