Name:       sdbd
Summary:    SDB daemon
Version: 0.0.2
Release:    3
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
%defattr(-,root,root,-) 
%{_prefix}/sbin/sdbd
%{_sysconfdir}/init.d/sdbd
%{_sysconfdir}/rc.d/rc3.d
%manifest sdbd.manifest

%changelog
* Wed Apr 18 2012 Yoonki Park <yoonki.park@samsung.com>
 - set dir permission to 777
* Sat Mar 31 2012 Yoonki Park <yoonki.park@samsung.com>
 - let sshd be daemon and create sshd.pid file
