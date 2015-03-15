Enigstore
=========


Motivation:

Enigmail is not able to manipulate the mails stored inside thunderbird.
Since the mails are only encrypted when viewed via enigmail,
there is no way to search through them.


**Enigstore** 

* Reads thunderbird mbox files.

* Writes a copy of that mbox file.

* For each gpg encrypted message that is found, it inserts a decrypted version of that message below the original one.


There is no support for netsted mails yet. Please send a test case or money.

There is no support for encrypted attachements.
They aren't searchable anyway..


**Please be aware that this is one of those 'works for me' solutions.**

**Use with caution! Do not trust me! Read the source!**

**This program could erase everything! ;)**

**Make backups! Have fun!**


Prerequisites:

Tested with ruby 2.1.5

You need to install the ruby mail gem:

```
$ gem install mail
```

Usage:

Shut down thunderbird
```
$ ruby enigstore.rb <input_file> <your_pass_phrase>
```

(that will leak your passphrase into $unwanted_places!
 no gpg-agent support yet)


Example:
```
$ ruby enigstore.rb /full/path/some_mbox_file "my passphrase is not here"
```

will create: /full/path/some_mbox_file-decrypted


