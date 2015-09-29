from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Store, Toy

engine = create_engine('sqlite:///toystores.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create user
user1 = User(name="Guy Fawkes", email="guy@example.com",
             picture="https://en.wikipedia.org/wiki/Guy_Fawkes_mask#/media/File:GuyFawkesMask.jpg")
session.add(user1)
session.commit()


# Toys from 5 little monkeys
store1 = Store(user_id=1, name="5 little monkeys", url="www.5littlemonkeys.com",
               address="1366 N. Main St., Walnut Creek, Ca 94596")

session.add(store1)
session.commit()

toy1 = Toy(user_id=1, name="Mini Bumble Bee",
           description="Small enough for tiny hands, large enough to make a big impression.",
           price=9.99, age_min=0, store=store1,
           img_url="http://stoysnetcdn.com/schy/schyb30335/schyb30335.jpg",
           url="http://www.5littlemonkeys.com/buy/2566/brio-mini-bumble-bee")

session.add(toy1)
session.commit()


toy2 = Toy(user_id=1, name="Baby Chimpanzee Hand Puppet",
           description="A hug-able puppet with a movable mouth and sweet expression.",
           price=24.99, age_min=4, store=store1,
           img_url="http://stoysnetcdn.com/fm/fm2877/fm2877_1.jpg",
           url="http://www.5littlemonkeys.com/buy/12480/baby-chimpanzee-hand-puppet")

session.add(toy2)
session.commit()


# Toys from Amazon
store2 = Store(user_id=1, name="Amazon", url="www.amazon.com")
session.add(store2)
session.commit()

toy1 = Toy(user_id=1, name="Snap Circuits Jr SC-100",
           description="Hands-on experience designing and building models of working electrical circuits.",
           price=20.99, age_min=7, store=store2,
           img_url="http://ecx.images-amazon.com/images/I/91lfaA93v0L._SX522_.jpg",
           url="http://www.amazon.com/Snap-Circuits-SC-100-Electronics-Discovery/dp/B00008BFZH")

session.add(toy1)
session.commit()

toy2 = Toy(user_id=1, name="ZOOB Creepy Glow Creatures",
           description="Click and pop together to form joints that rotate, limbs that extend, axles that spin.",
           price=15.99, age_min=6, store=store2,
           img_url="http://ecx.images-amazon.com/images/I/91t6YyxS3KL._SX522_.jpg",
           url="http://www.amazon.com/ZOOB-0Z14003-Creepy-Glow-Creatures/dp/B00IYGLABU")

session.add(toy2)
session.commit()

print "added toys!"
