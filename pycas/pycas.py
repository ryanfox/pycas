#!/usr/bin/python

import cgi
import hashlib
import logging
import os
import sys
import time
import urllib
import urlparse
import bs4

"""
Copyright 2011 Jon Rifkin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


-----------------------------------------------------------------------
  Usage
-----------------------------------------------------------------------

    Purpose
        Authenticate users against a CAS server from your python cgi scripts.

    Using in your script

        import pycas
        status, userid, cookie = pycas.login(CAS_SERVER, THIS_SCRIPT)

    Required Parameters

        - CAS_SERVER : the url of your CAS server (for example, https://login.yoursite.edu).
        - THIS_SCRIPT: the url of the calling python cgi script.

    Returned Values

        - status:  return code, 0 for success.
        - userid:  the user name returned by cas.
        - cookie:  when non-blank, send this cookie to the client's browser so it can authenticate for
                   the rest of the session.

    Optional Parmaters:
        - lifetime:  lifetime of the cookie in seconds, enforced by pycas. Default is 0, meaning unlimited lifetime.
        - path:      Authentication cookie applies for all urls under 'path'. Defaults to "/" (all urls).
        - protocol:  CAS protocol version.  Default is 2.  Can be set to 1.
        - secure:    Default is True, which authenticates for https connections only.
        - opt:       set to 'renew' or 'gateway' for these CAS options.

        Examples:
            status, userid, cookie = pycas.login(CAS_SERVER, THIS_SCRIPT, protocol=1, secure=True)
            status, userid, cookie = pycas.login(CAS_SERVER, THIS_SCRIPT, path="/cgi-bin/accts")

    Status Codes are listed below.
"""

# Secret used to produce hash.   This can be any string.  Hackers who know this string can forge
# this script's authentication cookie.
SECRET = "7e16162998eb7efafb1498f75190a937"

#  Name field for pycas cookie
PYCAS_NAME = "pycas"

#  CAS Staus Codes:  returned to calling program by login() function.
CAS_OK = 0              # CAS authentication successful.
CAS_COOKIE_EXPIRED = 1  # PYCAS cookie exceeded its lifetime.
CAS_COOKIE_INVALID = 2  # PYCAS cookie is invalid (probably corrupted).
CAS_TICKET_INVALID = 3  # CAS server ticket invalid.
CAS_GATEWAY = 4         # CAS server returned without ticket while in gateway mode.


#  Status codes returned internally by function get_cookie_status().
COOKIE_AUTH = 0        # PYCAS cookie is valid.
COOKIE_NONE = 1        # No PYCAS cookie found.
COOKIE_GATEWAY = 2     # PYCAS gateway cookie found.
COOKIE_INVALID = 3     # Invalid PYCAS cookie found.

#  Status codes returned internally by function get_ticket_status().
TICKET_OK = 0        # Valid CAS server ticket found.
TICKET_NONE = 1      # No CAS server ticket found.
TICKET_INVALID = 2   # Invalid CAS server ticket found.

CAS_MSG = (
    "CAS authentication successful.",
    "PYCAS cookie exceeded its lifetime.",
    "PYCAS cookie is invalid (probably corrupted).",
    "CAS server ticket invalid.",
    "CAS server returned without ticket while in gateway mode.",
)

# Log file for debugging
LOG_FILE = "/tmp/cas.log"
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s %(message)s')


def _parse_tag(string, tag):
    """
    Used for parsing xml.  Search string for the first occurence of <tag>.....</tag> and return text (stripped
    of leading and tailing whitespace) between tags.  Return "" if tag not found.
    """
    soup = bs4.BeautifulSoup(string, "xml")
    if soup.find(tag) is None:
        return ''
    return soup.find(tag).string.strip()


def _split2(string, sep):
    """Split string in exactly two pieces, return '' for missing pieces."""
    parts = string.split(sep, 1) + ["", ""]
    return parts[0], parts[1]


def _makehash(string, secret=SECRET):
    """Use hash and secret to encrypt string."""
    m = hashlib.md5()
    m.update(string)
    m.update(secret)
    return m.hexdigest()[0:8]


def _make_pycas_cookie(val, domain, path, secure, expires=None):
    """Form cookie."""
    pycascookie = "Set-Cookie: {}={};domain={};path={}".format(PYCAS_NAME, val, domain, path)
    if secure:
        pycascookie += ";secure"
    if expires:
        pycascookie += ";expires=" + expires
    return pycascookie


def _do_redirect(cas_host, service_url, opt, secure):
    """Send redirect to client.  This function does not return, i.e. it teminates this script."""
    cas_url = cas_host + "/cas/login?service=" + service_url
    if opt in ("renew", "gateway"):
        cas_url += "&{}=true".format(opt)

    #  Print redirect page to browser
    print("Refresh: 0; url={}".format(cas_url))
    print("Content-type: text/html")
    if opt == "gateway":
        domain, path = urlparse.urlparse(service_url)[1:3]
        print(_make_pycas_cookie("gateway", domain, path, secure))
    print("\nIf your browser does not redirect you, then please follow <a href=\"{}\">this link</a>.\n".format(cas_url))
    sys.exit(1)


def _decode_cookie(cookie_vals, lifetime=None):
    """
    Retrieve id from pycas cookie and test data for validity (to prevent malicious users from falsely authenticating).
    Return status and id (id will be empty string if unknown).
    """

    #  Test for now cookies
    if cookie_vals is None:
        return COOKIE_NONE, ""

    #  Test each cookie value
    cookie_attrs = []
    for cookie_val in cookie_vals:
        #  Remove trailing ;
        if cookie_val and cookie_val[-1] == ";":
            cookie_val = cookie_val[0:-1]

        #  Test for pycas gateway cookie
        if cookie_val == "gateway":
            cookie_attrs.append(COOKIE_GATEWAY)
        else:  # Test for valid pycas authentication cookie.
            # Separate cookie parts
            oldhash = cookie_val[0:8]
            timestr, cookieid = _split2(cookie_val[8:], ":")
            #  Verify hash
            if oldhash == _makehash(timestr + ":" + cookieid):
                #  Check lifetime
                if lifetime:
                    if str(int(time.time()+int(lifetime))) < timestr:
                        #  OK:  Cookie still valid.
                        cookie_attrs.append(COOKIE_AUTH)
                    else:
                        # ERROR:  Cookie exceeded lifetime
                        cookie_attrs.append(CAS_COOKIE_EXPIRED)
                else:
                    #  OK:  Cookie valid (it has no lifetime)
                    cookie_attrs.append(COOKIE_AUTH)

            else:
                #  ERROR:  Cookie value are not consistent
                cookie_attrs.append(COOKIE_INVALID)

    #  Return status according to attribute values

    #  Valid authentication cookie takes precedence
    if COOKIE_AUTH in cookie_attrs:
        return COOKIE_AUTH, cookieid
    #  Gateway cookie takes next precedence
    if COOKIE_GATEWAY in cookie_attrs:
        return COOKIE_GATEWAY, ""
    #  If we've gotten here, there should be only one attribute left.
    return cookie_attrs[0], ""


def _validate_cas_1(cas_host, service_url, ticket):
    """Validate ticket using cas 1.0 protocol."""
    #  Second Call to CAS server: Ticket found, verify it.
    cas_validate = cas_host + "/cas/validate?ticket=" + ticket + "&service=" + service_url
    f_validate = urllib.urlopen(cas_validate)
    #  Get first line - should be yes or no
    response = f_validate.readline()
    #  Ticket does not validate, return error
    if response == "no\n":
        f_validate.close()
        return TICKET_INVALID, ""
    #  Ticket validates
    else:
        #  Get id
        ticketid = f_validate.readline()
        f_validate.close()
        ticketid = ticketid.strip()
        return TICKET_OK, ticketid


def _validate_cas_2(cas_host, service_url, ticket, opt):
    """
    Validate ticket using cas 2.0 protocol
    The 2.0 protocol allows the use of the mutually exclusive "renew" and "gateway" options.
    """
    #  Second Call to CAS server: Ticket found, verify it.
    cas_validate = cas_host + "/cas/serviceValidate?ticket=" + ticket + "&service=" + service_url
    if opt:
        cas_validate += "&{}=true".format(opt)
    f_validate = urllib.urlopen(cas_validate)
    #  Get first line - should be yes or no
    response = f_validate.read()
    ticketid = _parse_tag(response, "cas:user")
    #  Ticket does not validate, return error
    if ticketid == "":
        return TICKET_INVALID, ""
    #  Ticket validates
    else:
        return TICKET_OK, ticketid


def _get_cookies():
    """Read cookies from env variable HTTP_COOKIE."""
    #  Read all cookie pairs
    try:
        cookie_pairs = os.getenv("HTTP_COOKIE").split()
    except AttributeError:
        cookie_pairs = []
    cookies = {}
    for cookie_pair in cookie_pairs:
        key, val = _split2(cookie_pair.strip(), "=")
        if key in cookies:
            cookies[key].append(val)
        else:
            cookies[key] = [val]
    return cookies


def _get_cookie_status():
    """Check pycas cookie."""
    cookies = _get_cookies()
    return _decode_cookie(cookies.get(PYCAS_NAME))


def _get_ticket_status(cas_host, service_url, protocol, opt):
    if "ticket" in cgi.FieldStorage():
        ticket = cgi.FieldStorage()["ticket"].value
        if protocol == 1:
            ticket_status, ticketid = _validate_cas_1(cas_host, service_url, ticket, opt)
        else:
            ticket_status, ticketid = _validate_cas_2(cas_host, service_url, ticket, opt)
        #  Make cookie and return id
        if ticket_status == TICKET_OK:
            return TICKET_OK, id
        #  Return error status
        else:
            return ticket_status, ""
    else:
        return TICKET_NONE, ""


def login(cas_host, service_url, lifetime=None, secure=True, protocol=2, path="/", opt=""):
    """
    Login to CAS and return user id.  Return status, userid, pycas_cookie.
    """
    # TODO lifetime isn't enforced

    #  Check cookie for previous pycas state, with is either
    #     COOKIE_AUTH    - client already authenticated by pycas.
    #     COOKIE_GATEWAY - client returning from CAS_SERVER with gateway option set.
    #  Other cookie status are
    #     COOKIE_NONE    - no cookie found.
    #     COOKIE_INVALID - invalid cookie found.
    cookie_status, cookieid = _get_cookie_status()

    if cookie_status == COOKIE_AUTH:
        logging.info('login valid for {}'.format(cookieid))
        return CAS_OK, cookieid, ""

    if cookie_status == COOKIE_INVALID:
        return CAS_COOKIE_INVALID, "", ""

    #  Check ticket ticket returned by CAS server, ticket status can be
    #     TICKET_OK      - a valid authentication ticket from CAS server
    #     TICKET_INVALID - an invalid authentication ticket.
    #     TICKET_NONE    - no ticket found.
    #  If ticket is ok, then user has authenticated, return id and
    #  a pycas cookie for calling program to send to web browser.
    ticket_status, ticketid = _get_ticket_status(cas_host, service_url, protocol, opt)

    if ticket_status == TICKET_OK:
        logging.info('ticket valid for {}'.format(ticketid))
        timestr = str(int(time.time()))
        hashvalue = _makehash(timestr + ":" + ticketid)
        cookie_val = hashvalue + timestr + ":" + ticketid
        domain = urlparse.urlparse(service_url)[1]
        return CAS_OK, ticketid, _make_pycas_cookie(cookie_val, domain, path, secure)

    elif ticket_status == TICKET_INVALID:
        return CAS_TICKET_INVALID, "", ""

    #  If unathenticated and in gateway mode, return gateway status and clear
    #  pycas cookie (which was set to gateway by do_redirect()).
    if opt == "gateway":
        if cookie_status == COOKIE_GATEWAY:
            domain, path = urlparse.urlparse(service_url)[1:3]
            #  Set cookie expiration in the past to clear the cookie.
            past_date = time.strftime("%a, %d-%b-%Y %H:%M:%S %Z", time.localtime(time.time()-48*60*60))
            return CAS_GATEWAY, "", _make_pycas_cookie("", domain, path, secure, past_date)

    #  Do redirect
    _do_redirect(cas_host, service_url, opt, secure)


#-----------------------------------------------------------------------
#  Test
#-----------------------------------------------------------------------


if __name__ == "__main__":

    CAS_SERVER = "https://login.uconn.edu"
    SERVICE_URL = "http://bluet.ucc.uconn.edu/~jon/cgi-bin/pycas.py"

    status, userid, cookie = login(CAS_SERVER, SERVICE_URL, secure=True, opt="gateway")

    print("Content-type: text/html")
    print(cookie)
    print()
    print("""
<html>
<head>
<title>
castest.py
</title>
<style type=text/css>
td {background-color: #dddddd; padding: 4px}
</style>
</head>
<body>
<h2>pycas.py</h2>
<hr>
""")
    #  Print browser parameters from pycas.login
    if "ticket" in cgi.FieldStorage():
        ticket = cgi.FieldStorage()["ticket"].value
    else:
        ticket = ""

    in_cookie = os.getenv("HTTP_COOKIE")

    print("""
<p>
<b>Parameters sent from browser</b>
<table>
<tr> <td>Ticket</td> <td>{}</td> </tr>
<tr> <td>Cookie</td> <td>{}</td> </tr>
</table>
</p>""".format(ticket, in_cookie))

    #  Print output from pycas.login
    print("""
<p>
<b>Parameters returned from pycas.login()</b>
<table>
<tr><td>status</td><td> <b>{}</b> - <i>{}</i></td></tr>
<tr><td>id</td><td> <b>{}</b></td></tr>
<tr><td>cookie</td><td> <b>{}</b></td></tr>
</table>
</p>
</body></html>""".format(status, CAS_MSG[status], userid, cookie))
