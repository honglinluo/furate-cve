import dataset
from config import ConfigReader
from src import utils

logger = utils.Logger(name=__name__)
config = ConfigReader()

__all__ = ['ConMySql']


class ConMySql:
    database = None
    cof = config.get('MYSQL')
    url = f"mysql://{cof.get('user')}:{cof.get('password')}@{cof.get('host')}/"

    def __new__(cls, database_name=None):
        cls.url += database_name or cls.cof.get('database')
        cls.database = dataset.connect(url=cls.url)
        return cls.database

    def close(self):
        self.database.close()

    def __del__(self):
        self.close()

    def __str__(self):
        return f"MySql connect: {self.cof.get('host')}\t{self.cof.get('database')}"
