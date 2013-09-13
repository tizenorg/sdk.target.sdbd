Name:       sdbd
Summary:    SDB daemon
Version:    2.2.8
Release:    1
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz
Requires(post): pkgmgr
Requires(post): pkgmgr-server
Requires(post): wrt
Requires(post): aul
Requires: default-files-tizen
Requires: sys-assert
Requires: debug-launchpad
Requires: dbus

%description
Description: SDB daemon


%prep
%setup -q

%build
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%make_install

%post
chsmack -a sdbd::home /home/developer
chsmack -t /home/developer

%files
%manifest sdbd.manifest
%defattr(-,root,root,-) 
%{_prefix}/sbin/sdbd
%{_prefix}/sbin/sdk_launch
%{_sysconfdir}/init.d/sdbd
/usr/share/license/%{name}

%ifarch %{ix86}
    %{_sysconfdir}/rc.d/rc3.d
%endif

%changelog
* Wed Apr 04 2013 Ho Namkoong <ho.namkoong@samsung.com>
 - supports platform gdbserver
* Mon Dec 02 2012 Yoonki Park <yoonki.park@samsung.com>
 - supports cs report service using inotify
* Mon Dec 02 2012 Yoonki Park <yoonki.park@samsung.com>
 - sdb code dropped from adb (Ice Cream Samdwich 4.1.1)
* Wed Apr 18 2012 Yoonki Park <yoonki.park@samsung.com>
 - set dir permission to 777
* Sat Mar 31 2012 Yoonki Park <yoonki.park@samsung.com>
 - let sshd be daemon and create sshd.pid file
