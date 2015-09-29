Abstract
========
Flask app for a toy stores catalog.
User can see all the stores registered so far, for each store its corresponding 
toys, and for each toy its details. Authenticated users can create new entries 
and update and delete their own entries. 

Each toy can have an associated image. This can be a link to a web location,
supplied in a text field, or a local photo, that is uploaded via an upload 
button and then copied in the static folder.

Authentication is available for FB and Google users. After successful 
authentication, the user's photo will be displayed in the menu.


Usage
=====

python database_setup.py
python populate_toystores.py
python project.py

App is then available at http://localhost:8000


Archive contents
================

* database_setup.py
   Create tables User, Store, Toy

* populate_toystores.py
   Script that populates the database

* project.py
   app logic

* static
		/styles.css
		 		Style sheet for html pages
		/dots.png
				Default blank photo for not logged in users

* templates
		/deletestore.html
		/deletestoretoy.html
		/editstore.html
		/editstoretoy.html
		/header.html
		/login.html
		/main.html
		/newstore.html
		/newstoretoy.html
		/publicstores.html
		/publicstoretoys.html
		/publictoy.html
		/recenttoys.html
		/sidebar.html
		/stores.html
		/storetoys.html
		/toy.html




* README.txt




