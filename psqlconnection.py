import psycopg2


class PSQLConnection(object):

    def __init__(self, app, db):

        self.db=psycopg2.connect(dbname=db,
                                 host="localhost",
                                 port="5432",
                                 user="postgres",
                                 password="FootBall24!!")

        

    def query_db(self, query, data=None):

        cur = self.db.cursor()
        result = cur.execute(query,data)

        if query[0:6].lower() == 'select':

            # if select, make result list of dicts
            
            r = [dict((cur.description[i][0], value) \
                           for i, value in enumerate(row)) for row in cur.fetchall()]
            cur.close()
            return json.dumps((r[0] if r else None) if one else r)
            
        elif query[0:6].lower() == 'insert':

            # if insert, return id

            self.db.commit()
            cur.close()
            return result.lastrowid

        else:

            # if update/delete commit and return nothing
            
            self.db.commit()
            cur.close()

def PSQLConnector(app, db):
    return PSQLConnection(app, db)