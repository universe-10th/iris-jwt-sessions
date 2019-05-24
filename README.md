# iris-jwt-sessions
A kind of fork of (Golang) Iris sessions that integrate with JWTs instead of cookies.

*Yes: this includes a fork of some files existing in the regular sessions and most of it is adapted to a new use. I seriously tried to reuse most of the objects involved in session handler, but they are mostly private and so I had to essentially copy them*.

Usage
-----

It is mostly used like `Sessions`, but instead of:

    var sessions *Sessions = sessions.NewSession(a config)
    var session *Session = sessions.Start(a context)

You invoke:

    var sessions *JWTSessions = sessions.NewSession(a config)
    var session *JWTSession = sessions.Start(a context)

This session reads and writes `Authorization: Bearer <token>`
headers instead of cookies. It mostly works like sessions, although
an ideal expiration time in backend should be quite longer (or even
perhaps no expiration at all).

You can also use the regular custom databases (e.g. redis, boltdb)
you use with regular sessions.

Since `Start` is a `func(context.Context) (something)` method, it can
be used as a `hero`-like dependency.