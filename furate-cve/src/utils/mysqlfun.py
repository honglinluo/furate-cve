# coding = utf-8
import pymysql

from base import importfile

'''
   def __init__(self, host=None, user=None, password="",
                 database=None, port=0, unix_socket=None,
                 charset='', sql_mode=None,
                 read_default_file=None, conv=None, use_unicode=None,
                 client_flag=0, cursorclass=Cursor, init_command=None,
                 connect_timeout=10, ssl=None, read_default_group=None,
                 compress=None, named_pipe=None,
                 autocommit=False, db=None, passwd=None, local_infile=False,
                 max_allowed_packet=16*1024*1024, defer_connect=False,
                 auth_plugin_map=None, read_timeout=None, write_timeout=None,
                 bind_address=None, binary_prefix=False, program_name=None,
                 server_public_key=None):
                 '''

conf = importfile.config_ini("../conf/confing.ini", "mysql")


class Pysql:
    conf = importfile.config_ini("../conf/confing.ini", "mysql")
    host_d = conf["host"]
    user_d = conf["user"]
    password_d = conf["password"]

    def __init__(self, database, host=host_d, user=user_d, password=password_d, port=3306, charset='utf8',
                 cursor_class="Cursor", connect_timeout=10):
        """
        :param host:  地址
        :param user:  用户名
        :param password:  密码
        :param database: 数据库名称
        :param port:  端口号
        :param charset: 字符集
        :param cursor class: 返回类型
        :param connect_timeout: 等待时间
        :return: 链接状态
        """
        self.database = database
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.charset = charset
        self.cursor_class = cursor_class
        self.connect_timeout = connect_timeout
        self.connect_mysql()

    def connect_mysql(self):
        try:
            self.connect = pymysql.connect(host=self.host, user=self.user, password=self.password, port=int(self.port),
                                           database=self.database, charset=self.charset, cursorclass=self.cursor_class,
                                           connect_timeout=self.connect_timeout)
        except ConnectionError as e:
            raise ConnectionError("数据库{host}连接失败，请检查后再连接{e}".format(host=self.host, e=e))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_mysql()

    def close_mysql(self):
        """
        关闭数据库
        :return: 数据库关闭状态
        """
        try:
            self.connect.close()
            code = True
            print("数据库关闭成功")
        except ConnectionError as e:
            code = False
            print(e)
        return code

    def select_table(self, sql, bverify=False):
        """
        查询数据表
        :param sql:   sql语句
        :param bverify: 是否为验证sql语句
        :return:  返回sql执行后的结果，如果是验证sql，返回0/1
        """
        cursor = pymysql.cursors.Cursor(self.connect)  # 创建游标
        # cursor = self.cursor.cursor(cursor=pymysql.cursors.Cursor)
        # cursor = self.connect.py.cursor()
        try:
            cursor.execute(sql)
            data = cursor.fetchall()  # 返回获取到的数据
            if bverify:
                info = data[0][0]
            elif len(data) > 0:
                info = data
            else:
                info = None
        except Exception as e:
            info = None
            print("查询失败,请检查sql语句：%s" % sql)
            print(e)
        cursor.close()  # 关闭游标
        return info

    def insert_data(self, sql, args):
        """
        插入数据
        :param sql:  sql语句   "INSERT INTO shuzi(no_1,no_2) VALUES (%s,%s);"
        :param args:  对应位置的值   [(11, 22),(33, 44)]
        :return:
        """
        cursor = pymysql.cursors.Cursor(self.connect)

        try:
            cursor.executemany(sql, args)
            self.connect.commit()
            print("===== 插入成功 =====")
        except Exception as e:
            if "1062" in str(e):
                for i in list(args):
                    sql_one = sql.split("(%s")[0] + str(i)
                    self.alter_data(sql_one)
            else:
                print("===== 插入失败 =====", e)
                self.connect.rollback()
        cursor.close()

    def alter_data(self, sql: str):
        """
        删除、修改数据
        :param sql: sql语句
        :return:
        """
        cursor = pymysql.cursors.Cursor(self.connect)
        try:
            cursor.execute(sql)
            self.connect.commit()
        except Exception as e:
            print(e)
            self.connect.rollback()
        cursor.close()

    def column_checking(self, table: str, columns: list = None):
        """
        查询表字段内容，如果入参有columns值，则验证column中的字段是不是该表的字段
        :param table: 需要查询的表
        :param columns: 需要验证的字段列表
        :return:
        """
        table_column = []
        select_column = rf"select column_name,COLUMN_TYPE from information_schema.COLUMNS where TABLE_SCHEMA=" \
                        rf"'{self.database}' and TABLE_NAME='{table}'"
        columns_r = self.select_table(select_column)
        if columns:
            for i in columns_r:
                table_column.append(i[0])
            if set(columns).issubset(set(table_column)):
                return True
            else:
                for column in columns:
                    if column not in table_column:
                        print(rf"字段 {column} 不在表中，请检查字段名称")
                return False
        else:
            return columns_r

    def one_table_select(self, table: str, select_column: list = None, where_info: dict = None, limit=None,
                         order_name=None, order_func=False):
        """
        查询语句自动拼接，目前只支持and和 =
        :param limit: 查询数的数量
        :param select_column: 字段列表
        :param table: 查询的表名称
        :param where_info: 查询语句的SQL
        :param order_name: 排序字段
        :param order_func: 排序方法  True:降序，False:升序
        :return:
        """
        select = "select "
        if select_column:
            if not self.column_checking(table, select_column):
                raise LookupError(rf"查询的字段不存在，请检查查询字段名称 \n {select_column}")

            select += str(",".join(select_column))
            select += rf" from {str(self.database)}.{table} "
        else:
            select += rf"* from {str(self.database)}.{table} "

        if where_info:
            where_column = list(where_info.keys())

            if not self.column_checking(table, where_column):
                raise LookupError(rf"条件判断的字段不存在，请检查条件字段 \n {where_column}")

            select += "where "
            for i in range(len(where_column)):
                values = "("
                for value in where_info[where_column[i]]:
                    values = values + "'" + value + "'"
                    if value != where_info[where_column[i]][-1]:
                        values += ","
                    else:
                        values += ")"

                select = select + str(where_column[i]) + " in " + values
                if i < len(where_column) - 1:
                    select += "and"

        if order_name:
            select += f" order by {order_name} "
            if order_func:
                select += "desc"
            else:
                select += "asc"

        if limit:
            select += rf" limit {str(limit)}"

        select += ";"
        print(select)
        select_data = self.select_table(select)

        return select_data

    def one_statement_insertion(self, table, insert_column, insert_data):
        """
        自动拼接sql语句进行数据插入
        :param table: 需要插入的表
        :param insert_column: 需要插入的字段 [colum1, colum2]
        :param insert_data: 需要插入的字段  [(11, 22),(33, 44)]
        """
        str_s = ""
        size = 10

        for i in range(len(insert_column)):
            str_s += "%s"
            if i < len(insert_column) - 1:
                str_s += ","
            else:
                str_s += ");"

        insert_sql = rf"insert into {self.database}.{table} ({','.join(insert_column)}) values ({str_s}"
        print(insert_sql)

        if self.column_checking(table, insert_column) and len(insert_data[0]) == len(insert_column):

            # 如果数据量小于30条，就直接插入数据
            if len(insert_data) < 20:
                self.insert_data(insert_sql, insert_data)
                return

                # 如果数据量大于20条，就使用循环的方式进行处理。
            # 为确保不会剩余1个数据，不然转换为 tuple 类型时会多出一个逗号，导致数据插入失败
            elif len(insert_data) // size == 1:
                size -= 2

            # 每次插入的数据不能太多，如果较多时使用此方法
            for i in range(len(insert_data) // size + 1):
                args_cut = tuple(insert_data[size * i: size * i + size])
                print("正在插入数据：", args_cut)

                self.insert_data(insert_sql, args_cut)
        else:
            raise LookupError(
                rf"插入错误，请检查插入字段或数据是否正确。\n {insert_column}{insert_data}")

    def query_alter(self, sql, args=None):
        """

        :param sql: sql语句
        :param args: 对应位置的值   [(11, 22),(33, 44)]
        :return:
        """
        if args:
            self.insert_data(sql, args)
        else:
            self.alter_data(sql)
        self.close_mysql()


def exchange_mysql(db_table, database=conf["database"], insert_data: list or tuple = None,
                   table_column: list = None, limit=None, where: dict = None):
    """
    数据库中数据交换
    :param where: 查询语句的where条件 字典格式
    :param limit: 查询数据的数量
    :param database: 数据库名称，查询数据库的时候使用
    :param table_column: 插入的字段
    :param db_table: MySQL数据库中的数据表名称
    :param insert_data: 职位数据, 如果有就判定为插入数据，没有的话就认为是查询数据
    :type insert_data: tuple or list
    :return: 查询数据时会返回有效的ip数据 [["ip", "port", "location"]]
    """
    db = Pysql(host=conf["host"], user=conf["user"], password=conf["password"],
               database=database)

    if insert_data:
        if not table_column:
            raise TypeError("参数错误：执行插入语句时需要传入 table_column 参数")
        db.one_statement_insertion(table=db_table, insert_column=table_column, insert_data=insert_data)
        db.close_mysql()
    else:
        out_post_data = db.one_table_select(table=db_table, select_column=table_column, where_info=where, limit=limit)
        db.close_mysql()

        return out_post_data


if __name__ == '__main__':
    """
    # select = "SELECT COUNT(*)=1 FROM shuzi WHERE no_1=12;"  # 查询数据库中的jobs表
    # insert1 = "DELETE FROM shuzi WHERE no_1=12;"  # 在shuzi表中添加数据
    # insert2 = "INSERT INTO shuzi(no_1,no_2) VALUES (%s,%s);"
    # insert21 = [(12, 22), (33, 44)]
    # delete = "DELETE FROM shuzi WHERE no_1 = 1"  # 删除库中数据
    column = ["ip", "port", "location"]
    database_table = "internet_protocol_pool"
    dbs = Pysql()
    # dbs.connectSQL()    # 访问本机数据库
    # s = dbs.query_select(select, True)
    # dbs.closeSQL()
    # dbs.query_alter(insert1)
    # s = dbs.query_select(select, True)
    # dbs.query_alter(insert2, insert21)
    # for i in s:
    #     print(i)
    # print(s)
    # dbs.one_statement_insertion("test_ct", ["id", "name"], [("3", "z"), ("4", "b")])
    # insert_data = dbs.one_table_select("test_ct", select_column=["id", "name"], where_info={"name": ["z", "b"]})
    data = dbs.one_table_select()
    dbs.close_mysql()
    print(data)
    """
