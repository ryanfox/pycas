===============
pycas v0.0.2
===============

What?
===============
This is a copy of Jon Rifkin's Python CAS client.  The original can be found at
https://wiki.jasig.org/display/CASC/Pycas.  This fork lives at https://github.com/ryanfox/pycas and on Pypi.

The original appears to have not been updated for some time now, and is not on Pypi. This is an attempt to rectify
that situation.

Potential things to be added:
    - Unit tests
    - Better security
    - Enforce the timeout

Installation
==============
::

    pip install pycas

Why?
==============
The pycas CAS client provides CAS authentication for your Python CGI web application.

How?
==============
STEPS TO ADD CAS AUTHENTICATION

1) Add four lines to your Python Web app like this: ::

    from pycas import pycas
    CAS_SERVER  = "https://casserver.mydomain"
    SERVICE_URL = "http://webserver.mydomain/cgi-bin/webapp.py"
    status, userid, cookie = pycas.login(CAS_SERVER, SERVICE_URL)

2) Process the returned variables::

    status carries the success or failure status.
    userid is the user's account name.
    cookie is the header string to send to the client if it's not empty.

For more information, see comments in the Python code.
