Name:       sdbd
Summary:    SDB daemon
Version: 0.0.3
Release:    2
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz
Source1:    sdbd.manifest

%description
Description: SDB daemon


%prep
%setup -q

%build
cp %{SOURCE1} .
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
%make_install

%if 0%{?simulator}
	install -d 0755 %{buildroot}/%{_sysconfdir}/rc.d/rc3.d
	ln -sf /etc/init.d/sdbd %{buildroot}/%{_sysconfdir}/rc.d/rc3.d/S06sdbd
%endif

%files
%manifest sdbd.manifest
%defattr(-,root,root,-) 
%{_prefix}/sbin/sdbd
%{_sysconfdir}/init.d/sdbd

%if 0%{?simulator}
	%dir %{_sysconfdir}/rc.d/rc3.d
	%{_sysconfdir}/rc.d/rc3.d/S06sdbd
%endif


%changelog
* Mon Dec 02 2012 Yoonki Park <yoonki.park@samsung.com>
 - supports cs report service using inotify
* Mon Dec 02 2012 Yoonki Park <yoonki.park@samsung.com>
 - sdb code dropped from adb (Ice Cream Samdwich 4.1.1)
* Wed Apr 18 2012 Yoonki Park <yoonki.park@samsung.com>
 - set dir permission to 777
* Sat Mar 31 2012 Yoonki Park <yoonki.park@samsung.com>
 - let sshd be daemon and create sshd.pid file
