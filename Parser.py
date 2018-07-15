import mysql.connector
from mysql.connector import errorcode
import time

#credentials for mySQL login
user = 'root'
password = 'P@ssw0rd'
host = '10.0.0.14'
database = 'siem'

file_log = 'C:\Users\Owner\PycharmProjects\My Python Work\Projects\SIEM\ScapyLogs.txt'
#ping sweep file_log = 'C:\Users\Owner\Downloads\Ping_Sweep.txt'
#port scan file_log = 'C:\Users\Owner\Downloads\Port_Scan.txt'

def ConnectToDB():
    'Function which connects to mySQL database. Returns a connection or an error message'
    try:
        cnx = mysql.connector.connect(user=user, password=password,
                                      host=host, database=database)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None


def PortToProtocol(portnumber):
    'dictionary from port number to port names'
    PORTS = {'21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '67': 'DHCP', '53': 'DNS', '80': 'HTTP', '445': 'SMB', '443': 'HTTPS'}
    if portnumber in PORTS.keys():
        return PORTS[portnumber]
    else:
        return 'UNKNOWN'


def LogToDct(line_of_file):
    'convert each line of log file into dictionary'
    log_list = line_of_file.split()
    dct = {}
    dct['DATE'] = log_list[0] + ' ' + log_list[1]
    dct['SRC_IP'] = log_list[2]
    dct['DST_IP'] = log_list[3]
    dct['PORT'] = log_list[4]
    dct['ACTION'] = log_list[5]
    dct['PROTOCOL'] = PortToProtocol(dct['PORT'])
    return dct


def InsertToDB(log, cnx, cursor):
    'inserting logs in mySQL database query'
    add_log = ("""INSERT INTO fwlogs
                (ID, DATE, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION)
                VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    cursor.execute(add_log, log)
    cnx.commit()


def insert_logs(log, cnx, cursor):
    'reads each line of log file and inserts each log into mySQL database. Contains while True and sleep so that it doesnt keep trying to add lines when there are no new ones'
    with open(log, 'r') as logs:
        while True:
            line = logs.readline()
            if line:
                dct = LogToDct(line)
                InsertToDB(dct, cnx, cursor)
            else:
                time.sleep(0.1)


def main():
    cnx, cursor = ConnectToDB()
    query = ("SELECT * FROM fwlogs")
    cursor.execute(query)
    insert_logs(file_log, cnx, cursor)
    cursor.close()
    cnx.close()


if __name__ == '__main__':
    main()








