from peewee import SqliteDatabase, Model, CharField


db = SqliteDatabase('database.db')


class Config(Model):
    k8s_config_path = CharField()
    kubectl_path = CharField()
    telepresence_path = CharField()
    sudo_password = CharField()

    class Meta:
        database = db


class Telepresence(Model):
    k8s_file = CharField()
    state = CharField()

    class Meta:
        database = db


class HostConfig(Model):
    k8s_file = CharField()

    class Meta:
        database = db


class Host(Model):
    namespace = CharField()
    name= CharField()
    ip= CharField()

    class Meta:
        database = db


class Portforward(Model):
    key = CharField()
    subprocess_id = CharField()

    class Meta:
        database = db
