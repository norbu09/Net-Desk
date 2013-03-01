use 5.006;
use strict;
use warnings FATAL => 'all';
use inc::Module::Install;

name     'Net-Desk';
all_from 'lib/Net/Desk.pm';
author   q{Lenz Gschwendtner <norbu09@cpan.org>};
license  'artistic2';

perl_version 5.006;

tests_recursive('t');

resources (
   #homepage   => 'http://yourwebsitehere.com',
   #IRC        => 'irc://irc.perl.org/#Net-Desk',
   license    => 'http://www.perlfoundation.org/artistic_license_2_0',
   #repository => 'git://github.com/Lenz Gschwendtner/Net-Desk.git',
   bugtracker => 'http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Desk',
);

configure_requires (
   'Module::Install' => 0,
);

build_requires (
   'Test::More' => 0,
);

requires (
   #'ABC'              => 1.6,
   #'Foo::Bar::Module' => 5.0401,
);

install_as_cpan;
auto_install;
WriteAll;
