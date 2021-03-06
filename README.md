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

I used the Vagrant virtual environment provided by udacity, and on top 
of that I also installed:
- dicttoxml 1.6.6
- Flask-SeaSurf 0.2.1

Prior to running, the app needs some basic setup for OAuth2 authentication.

* Google+

    Go to _console.developers.google.com_ and create an app named Toy Store.  
    In the _APIs & auth > Credentials > OAuth consent screen_ section, add your 
    google email address and set the Product name to 'Toy Store'.

    In the _APIs & auth > Credentials_ section, add the following:  
      - __Name__ - Toy Store  
      - __Authorized JavaScript origins__ - http://localhost:8000  
      - __Authorized redirect URIs__ - http://localhost:8000/login  

    Then download the JSON file, and save it as _client_secrets.json_ in the 
    same folder as project.py  

    Also, in _templates/login.html_, update _data-clientid_ to the one assigned
    by Google (Client ID for Web application).

* facebook

    Go to _developers.facebook.com_ and create a new web app with:
      - __Display name__ - Toy Store  
      - __Contact Email__ - your email  
      - __Site URL__ - http://localhost:8000/  

    In _templates/login.html_, in FB.init(), update the _appId_ field to the
    App ID value given by facebook.

    Also, create a file called _fb_client_secrets.json_ in the same folder as 
    project.py and insert the following content

    ```
    {
      "web": {
        "app_id": "xyz",
        "app_secret": "zyx"
      }
    }
    ```  
    where:
      - __app_id__ - the facebook App ID  
      - __app_secret__ - the facebook App Secret   


After this setup, run the following commands:

```
python database_setup.py
python populate_toystores.py
python project.py
```

App is then available at _http://localhost:8000_

Access JSON and XML endpoints here:
_http://localhost:8000/stores/JSON/_
_http://localhost:8000/stores/<int:store_id>/toys/JSON/_
_http://localhost:8000/stores/<int:store_id>/toy/<int:toy_id>/JSON/_
_http://localhost:8000/stores/XML/_
_http://localhost:8000/stores/<int:store_id>/toys/XML/_
_http://localhost:8000/stores/<int:store_id>/toy/<int:toy_id>/XML/_


Archive contents
================

```
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

* README.md
```
