'''
Copyright (c) 2011-2017, Agora Games, LLC All rights reserved.

https://github.com/agoragames/haigha/blob/master/LICENSE.txt
'''

from chai import Chai

from haigha2.message import Message


class MessageTest(Chai):

    def test_init_no_args(self):
        m = Message()
        self.assertEqual('', m._body)
        self.assertEqual(None, m._delivery_info)
        self.assertEqual(None, m.return_info)
        self.assertEqual({}, m._properties)

    def test_init_with_delivery_and_args(self):
        m = Message('foo', 'delivery', foo='bar')
        self.assertEqual('foo', m._body)
        self.assertEqual('delivery', m._delivery_info)
        self.assertEqual({'foo': 'bar'}, m._properties)

        m = Message('D\xfcsseldorf')
        self.assertEqual('D\xc3\xbcsseldorf', m._body)
        self.assertEqual({'content_encoding': 'utf-8'}, m._properties)

    def test_with_body_and_properties(self):
        m = Message('foo', foo='bar')
        self.assertEqual('foo', m.body)
        self.assertEqual(None, m.delivery_info)
        self.assertEqual(None, m.return_info)
        self.assertEqual({'foo': 'bar'}, m.properties)

    def test_with_delivery_and_properties(self):
        m = Message('foo', 'delivery', foo='bar')
        self.assertEqual('foo', m.body)
        self.assertEqual('delivery', m.delivery_info)
        self.assertEqual(None, m.return_info)
        self.assertEqual({'foo': 'bar'}, m.properties)

    def test_with_return_and_properties(self):
        m = Message('foo', return_info='return', foo='bar')
        self.assertEqual('foo', m.body)
        self.assertEqual('return', m.return_info)
        self.assertEqual(None, m.delivery_info)
        self.assertEqual({'foo': 'bar'}, m.properties)

    def test_len(self):
        m = Message('foobar')
        self.assertEqual(6, len(m))

    def test_nonzero(self):
        m = Message()
        self.assertTrue(m)

    def test_eq(self):
        l = Message()
        r = Message()
        self.assertEqual(l, r)

        l = Message('foo')
        r = Message('foo')
        self.assertEqual(l, r)

        l = Message(foo='bar')
        r = Message(foo='bar')
        self.assertEqual(l, r)

        l = Message('hello', foo='bar')
        r = Message('hello', foo='bar')
        self.assertEqual(l, r)

        l = Message('foo')
        r = Message('bar')
        self.assertNotEqual(l, r)

        l = Message(foo='bar')
        r = Message(foo='brah')
        self.assertNotEqual(l, r)

        l = Message('hello', foo='bar')
        r = Message('goodbye', foo='bar')
        self.assertNotEqual(l, r)

        l = Message('hello', foo='bar')
        r = Message('hello', foo='brah')
        self.assertNotEqual(l, r)

        self.assertNotEqual(Message(), object())

    def test_str_with_delivery_info(self):
        m = Message('foo', 'delivery', foo='bar')
        str(m)

    def test_str_with_return_info(self):
        m = Message('foo', return_info='returned', foo='bar')
        str(m)
