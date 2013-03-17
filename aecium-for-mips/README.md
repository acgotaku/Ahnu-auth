//////////////////////////////////////////////////////////////////////////

	aecium - Amtium eFlow Client for GNU/Linux

/////////////////////////////////////////////////////////////////////////


Description
===========

"aecium" is designed to access Internet when the ethernet your computer belong to is
controled by Amtium eFlow. Amtium eFlow is a product produced by Amtium Corporation.
Many of university in China control their ethernet using Amtium eFlow. But they provide
a software which you can only use to access Internet under Windows, but not GNU/Linux.
This is why "aecium" appears in your eye.

As I know, Amtium eFlow is a BAS-Based authentication service product, that means maybe
you can use "aecium" to access Internet when the ethernet you computer belong to is
controled by another BAS-Based authentication service product, such as D-Link edu.

This program is released under the GNU General Public License (GPL) version 2,
see the file 'COPYING' for more information.



Usage
=====

Type "aecium --help" for more information.
When you are using "aecium" for the first time, you should provide entire information the
procedure need. Two ways can help you. To input whole argument to the command line is the
first way. For example:

$aecium --username=your-name --password=your-password --host=server-host-ip --device=network-card-interface-eg-eth0 --service

To create a file named ".aecium" in which you need to provide the information the procedure
need under your home directory is the second way. Structure in file ".aecium" must be like
this:

host=server-host-ip-eg-210.45.193.3
service=service-type-eg-int
interface=network-card-interface-eg-eth0

