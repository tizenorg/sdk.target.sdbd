Name:       sdbd
Summary:    SDB daemon
Version:    2.0.2
Release:    2
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz

%description
Description: SDB daemon


%prep
%setup -q

%build
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
%make_install

%files
%manifest sdbd.manifest
%defattr(-,root,root,-) 
%{_prefix}/sbin/sdbd
%{_sysconfdir}/init.d/sdbd
%{_sysconfdir}/rc.d/rc3.d

%changelog
* Mon Dec 02 2012 Yoonki Park <yoonki.park@samsung.com>
 - supports cs report service using inotify
* Mon Dec 02 2012 Yoonki Park <yoonki.park@samsung.com>
 - sdb code dropped from adb (Ice Cream Samdwich 4.1.1)
* Wed Apr 18 2012 Yoonki Park <yoonki.park@samsung.com>
 - set dir permission to 777
* Sat Mar 31 2012 Yoonki Park <yoonki.park@samsung.com>
 - let sshd be daemon and create sshd.pid file
