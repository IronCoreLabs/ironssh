# Don't bother building a debug package. Open source so people can go nuts
# debugging source code if desired.
%define debug_package %{nil}

# Some openssh binaries will also be built and should be ignored
%define _unpackaged_files_terminate_build 0

Summary: The IronCore fork of OpenSSH adding transparent E2E encryption to file transfers
Name: ironssh
Version: PLACEHOLDER
Release: PLACEHOLDER
URL: https://github.com/ironcorelabs/ironssh
Source0:  PLACEHOLDER
License: BSD
Group: Applications/Internet
#BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
Requires: openssh-clients
Requires: libedit >= 3.0
Requires: libsodium >= 1.0
BuildRequires: autoconf
BuildRequires: libsodium-devel >= 1.0
BuildRequires: libedit-devel >= 3.0
BuildRequires: perl, openssl-devel, make, glibc-devel

%description
IronSSH is a fork of OpenSSH that brings automatic end-to-end encryption
to sftp and scp in the form of new tools, ironsftp and ironscp. When
uploading files to remote servers, they are encrypted in a GPG 2.1
compatible format using Curve25519 crypto. These files stay encrypted on
the server and are transparently decrypted on download. Files may be shared
with other users on the server who have logged in via ironsftp at least once.

%prep

%setup -q

%build
autoreconf

%configure \
  --sysconfdir=%{_sysconfdir}/ssh \
  --libexecdir=%{_libexecdir}/openssh \
  --datadir=%{_datadir}/openssh \
  --with-default-path=/usr/local/bin:/bin:/usr/bin \
  --with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin \
  --with-privsep-path=%{_var}/empty/sshd \
  --with-md5-passwords \
  --with-libedit

make

%install
rm -rf $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

%check
make iron-tests

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc CREDITS INSTALL LICENCE OVERVIEW README* PROTOCOL* TODO
#%attr(0755,root,root) %{_bindir}/ironscp
#%attr(0644,root,root) %{_mandir}/man1/ironscp.1*
%attr(0755,root,root) %{_bindir}/ironsftp
%attr(0644,root,root) %{_mandir}/man1/ironsftp.1*

%changelog
* Mon Aug 22 2016 Patrick Walsh <patrick.walsh@ironcorelabs.com>
- Initial setup
