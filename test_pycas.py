import unittest


class TestPycas(unittest.TestCase):

    def test_parse_tag(self):
        from pycas.pycas import _parse_tag
        xml = '<tag1><tag2>here is some data</tag2><tag2>here is some other data</tag2></tag1>'
        self.assertEqual(_parse_tag(xml, 'tag2'), 'here is some data')
        self.assertEqual(_parse_tag(xml, 'notag'), '')

    def test_split2(self):
        from pycas.pycas import _split2
        self.assertEqual(_split2('', 'anything'), ('', ''))
        self.assertEqual(_split2('aaaabcccc', 'b'), ('aaaa', 'cccc'))
        self.assertEqual(_split2('aaaabccccbdddd', 'b'), ('aaaa', 'ccccbdddd'))
        self.assertEqual(_split2('foo', 'z'), ('foo', ''))

    def test_makehash(self):
        from pycas.pycas import _makehash
        self.assertEqual(_makehash('12345', '67890'), 'e807f1fc')  # generated with `echo -n "1234567890" | md5sum`

    def test_make_pycas_cookie(self):
        from pycas.pycas import _make_pycas_cookie
        cookie = _make_pycas_cookie('hashedvalue', 'example.com', '/path/to/stuff', secure=True, expires='Sun, 13-Jul-2014 13:12:06 MDT')
        self.assertEqual(cookie, "Set-Cookie: pycas=hashedvalue;domain=example.com;path=/path/to/stuff;secure;expires=Sun, 13-Jul-2014 13:12:06 MDT")

if __name__ == '__main__':
    unittest.main()