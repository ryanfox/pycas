===============
pycas v0.0.1
===============

Why?
===============
This is a copy of the Jasig pycas client.  The original can be found at https://wiki.jasig.org/display/CASC/Pycas

However, it is neither easy to find nor on Pypi.  This is an attempt to rectify that situation.

How?
==============
    pip install pycas

The pycas CAS client provides CAS authentication for your Python CGI web application.

STEPS TO ADD CAS AUTHENTICATION

1) Add four lines to your Python Web app like this: ::

    from pycas import pycas
    CAS_SERVER  = "https://casserver.mydomain"
    SERVICE_URL = "http://webserver.mydomain/cgi-bin/webapp.py"
    status, id, cookie = login(CAS_SERVER, SERVICE_URL)

2) Process the returned variables, ::

    status carries the success or failure status.
    id is the user's account name.
    cookie is the header string to send to the client if it's not empty.

For more information, see comments in the Python code.
