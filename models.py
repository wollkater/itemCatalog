from sqlalchemy import create_engine, Column, Integer, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    email = Column(Text, index=True)
    picture = Column(Text)


class Item(Base):
    __tablename__ = "item"

    id = Column(Integer, primary_key=True)
    name = Column(Text)
    description = Column(Text)
    created_by = Column(Text)
    category_id = Column(Integer, ForeignKey("category.id"))

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'created_by': self.created_by,
            'category_id': self.category_id
        }


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(Text)
    items = relationship(Item)
    created_by = Column(Text)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'created_by': self.created_by,
            'items': [i.serialize for i in self.items]
        }


engine = create_engine('sqlite:///itemCatalog.db')

Base.metadata.create_all(engine)