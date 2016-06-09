﻿#!/bin/python
#-*-conding:utf-8-*-
''''
用指定hash算法对样本加载DLL导出函数进行hash计算，将计算结果保存为json格式

注意: 使用当前脚本时，需要根据不同样本修改某些配置，具体如下：
        1. max_bits ： 进行位移运算数据的Bit位数
        2. hash_function1 ：进行hash计算的算法
        3. custom_dlls ： 样本使用到的DLL
        4. 由于当前脚本使用了中文注释，所以必须保证当前样本编码格式为UTF-8.
'''


import pefile, os, re, binascii, json

max_bits = 32

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
	

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
	

# add new hash_funcation in here
def hash_function1(name):
	x = 0x00000000
	i = 9
	for n in name:
		x = rol(x, 7, max_bits) ^ ord(n)
	x = x & 0xFFFFFFFF
	le = len(hex(x))
	return x
	#return ('0' * (11-le)) + hex(x)[2:le-1]  #return hex format



def calc_crc32(string):
	''' 
	Simple helper function to calculate the hex-encoded CRC32 hash of the 
	supplied data.
	'''
	return hex(binascii.crc32(string) & 0xFFFFFFFF)


# Data acquired via http://xpdll.nirsoft.net/
most_common_dlls = ['aaaamon.dll', 'aaclient.dll', 'acctres.dll', 'acledit.dll', 'aclui.dll', 'activeds.dll', 'actxprxy.dll', 'admparse.dll', 'adptif.dll', 'adsldp.dll', 'adsldpc.dll', 'adsmsext.dll', 'adsnds.dll', 'adsnt.dll', 'adsnw.dll', 'advapi32.dll', 'advpack.dll', 'alrsvc.dll', 'amstream.dll', 'apcups.dll', 'apphelp.dll', 'appmgmts.dll', 'appmgr.dll', 'asferror.dll', 'asycfilt.dll', 'atkctrs.dll', 'atl.dll', 'atmpvcno.dll', 'atrace.dll', 'audiosrv.dll', 'authz.dll', 'autodisc.dll', 'avicap32.dll', 'avifil32.dll', 'avmeter.dll', 'avtapi.dll', 'avwav.dll', 'azroles.dll', 'basesrv.dll', 'batmeter.dll', 'batt.dll', 'bidispl.dll', 'bitsprx2.dll', 'bitsprx3.dll', 'bitsprx4.dll', 'blackbox.dll', 'bootvid.dll', 'browselc.dll', 'browser.dll', 'browseui.dll', 'browsewm.dll', 'bthci.dll', 'bthserv.dll', 'btpanui.dll', 'c_g18030.dll', 'c_is2022.dll', 'c_iscii.dll', 'cabinet.dll', 'cabview.dll', 'camocx.dll', 'capesnpn.dll', 'cards.dll', 'catsrv.dll', 'catsrvps.dll', 'catsrvut.dll', 'ccfgnt.dll', 'cdfview.dll', 'cdm.dll', 'cdmodem.dll', 'cdosys.dll', 'certcli.dll', 'certmgr.dll', 'cewmdm.dll', 'cfgbkend.dll', 'cfgmgr32.dll', 'chsbrkr.dll', 'chtbrkr.dll', 'ciadmin.dll', 'cic.dll', 'ciodm.dll', 'clb.dll', 'clbcatex.dll', 'clbcatq.dll', 'cliconfg.dll', 'clusapi.dll', 'cmcfg32.dll', 'cmdial32.dll', 'cmpbk32.dll', 'cmprops.dll', 'cmsetacl.dll', 'cmutil.dll', 'cnbjmon.dll', 'cnetcfg.dll', 'cnvfat.dll', 'colbact.dll', 'comaddin.dll', 'comcat.dll', 'comctl32.dll', 'comdlg32.dll', 'compstui.dll', 'comrepl.dll', 'comres.dll', 'comsnap.dll', 'comsvcs.dll', 'comuid.dll', 'confmsp.dll', 'console.dll', 'corpol.dll', 'credssp.dll', 'credui.dll', 'crtdll.dll', 'crypt32.dll', 'cryptdlg.dll', 'cryptdll.dll', 'cryptext.dll', 'cryptnet.dll', 'cryptsvc.dll', 'cryptui.dll', 'cscdll.dll', 'cscui.dll', 'csrsrv.dll', 'csseqchk.dll', 'ctl3d32.dll', 'd3d8.dll', 'd3d8thk.dll', 'd3d9.dll', 'd3dim.dll', 'd3dim700.dll', 'd3dpmesh.dll', 'd3dramp.dll', 'd3drm.dll', 'd3dxof.dll', 'danim.dll', 'dataclen.dll', 'datime.dll', 'davclnt.dll', 'dbgeng.dll', 'dbghelp.dll', 'dbmsrpcn.dll', 'dbnetlib.dll', 'dbnmpntw.dll', 'dciman32.dll', 'ddraw.dll', 'ddrawex.dll', 'deskadp.dll', 'deskmon.dll', 'deskperf.dll', 'devenum.dll', 'devmgr.dll', 'dfrgres.dll', 'dfrgsnap.dll', 'dfrgui.dll', 'dfsshlex.dll', 'dgnet.dll', 'dhcpcsvc.dll', 'dhcpmon.dll', 'dhcpqec.dll', 'dhcpsapi.dll', 'diactfrm.dll', 'digest.dll', 'dimap.dll', 'dimsntfy.dll', 'dimsroam.dll', 'dinput.dll', 'dinput8.dll', 'diskcopy.dll', 'dispex.dll', 'dmband.dll', 'dmcompos.dll', 'dmconfig.dll', 'dmdlgs.dll', 'dmdskmgr.dll', 'dmdskres.dll', 'dmime.dll', 'dmintf.dll', 'dmloader.dll', 'dmocx.dll', 'dmscript.dll', 'dmserver.dll', 'dmstyle.dll', 'dmsynth.dll', 'dmusic.dll', 'dmutil.dll', 'dnsapi.dll', 'dnsrslvr.dll', 'docprop.dll', 'docprop2.dll', 'dot3api.dll', 'dot3cfg.dll', 'dot3dlg.dll', 'dot3gpclnt.dll', 'dot3msm.dll', 'dot3svc.dll', 'dot3ui.dll', 'dpcdll.dll', 'dplay.dll', 'dplayx.dll', 'dpmodemx.dll', 'dpnaddr.dll', 'dpnet.dll', 'dpnhpast.dll', 'dpnhupnp.dll', 'dpnlobby.dll', 'dpnmodem.dll', 'dpnwsock.dll', 'dpserial.dll', 'dpvacm.dll', 'dpvoice.dll', 'dpvvox.dll', 'dpwsock.dll', 'dpwsockx.dll', 'drmclien.dll', 'drmstor.dll', 'drmv2clt.dll', 'drprov.dll', 'ds32gt.dll', 'dsauth.dll', 'dsdmo.dll', 'dsdmoprp.dll', 'dskquota.dll', 'dskquoui.dll', 'dsound.dll', 'dsound3d.dll', 'dsprop.dll', 'dsprpres.dll', 'dsquery.dll', 'dssec.dll', 'dssenh.dll', 'dsuiext.dll', 'dswave.dll', 'duser.dll', 'dx7vb.dll', 'dx8vb.dll', 'dxdiagn.dll', 'dxmasf.dll', 'dxtmsft.dll', 'dxtrans.dll', 'eapolqec.dll', 'eapp3hst.dll', 'eappcfg.dll', 'eappgnui.dll', 'eapphost.dll', 'eappprxy.dll', 'eapqec.dll', 'eapsvc.dll', 'efsadu.dll', 'els.dll', 'encapi.dll', 'encdec.dll', 'ersvc.dll', 'es.dll', 'esent.dll', 'esent97.dll', 'esentprf.dll', 'eventcls.dll', 'eventlog.dll', 'expsrv.dll', 'extmgr.dll', 'exts.dll', 'f3ahvoas.dll', 'faultrep.dll', 'fde.dll', 'fdeploy.dll', 'feclient.dll', 'filemgmt.dll', 'fldrclnr.dll', 'fltlib.dll', 'fmifs.dll', 'fontext.dll', 'fontsub.dll', 'framebuf.dll', 'fsusd.dll', 'ftlx041e.dll', 'ftsrch.dll', 'fwcfg.dll', 'gcdef.dll', 'gdi32.dll', 'getuname.dll', 'glmf32.dll', 'glu32.dll', 'gpedit.dll', 'gpkcsp.dll', 'gpkrsrc.dll', 'gptext.dll', 'h323msp.dll', 'hccoin.dll', 'hhsetup.dll', 'hid.dll', 'hlink.dll', 'hnetcfg.dll', 'hnetmon.dll', 'hnetwiz.dll', 'hotplug.dll', 'httpapi.dll', 'htui.dll', 'iasacct.dll', 'iasads.dll', 'iashlpr.dll', 'iasnap.dll', 'iaspolcy.dll', 'iasrad.dll', 'iasrecst.dll', 'iassam.dll', 'iassdo.dll', 'iassvcs.dll', 'icaapi.dll', 'icardie.dll', 'icfgnt5.dll', 'icm32.dll', 'icmp.dll', 'icmui.dll', 'icwdial.dll', 'icwphbk.dll', 'idndl.dll', 'idq.dll', 'ieakeng.dll', 'ieaksie.dll', 'ieakui.dll', 'ieapfltr.dll', 'iedkcs32.dll', 'ieframe.dll', 'iepeers.dll', 'iernonce.dll', 'iertutil.dll', 'iesetup.dll', 'ieui.dll', 'ifmon.dll', 'ifsutil.dll', 'igmpagnt.dll', 'iissuba.dll', 'ils.dll', 'imagehlp.dll', 'imeshare.dll', 'imgutil.dll', 'imjp81k.dll', 'imm32.dll', 'inetcfg.dll', 'inetcomm.dll', 'inetcplc.dll', 'inetmib1.dll', 'inetpp.dll', 'inetppui.dll', 'inetres.dll', 'infosoft.dll', 'initpki.dll', 'input.dll', 'inseng.dll', 'iologmsg.dll', 'iphlpapi.dll', 'ipmontr.dll', 'ipnathlp.dll', 'ippromon.dll', 'iprop.dll', 'iprtprio.dll', 'iprtrmgr.dll', 'ipsecsnp.dll', 'ipsecsvc.dll', 'ipsmsnap.dll', 'ipv6mon.dll', 'ipxmontr.dll', 'ipxpromn.dll', 'ipxrip.dll', 'ipxrtmgr.dll', 'ipxsap.dll', 'ipxwan.dll', 'irclass.dll', 'isign32.dll', 'itircl.dll', 'itss.dll', 'iuengine.dll', 'ixsso.dll', 'iyuv_32.dll', 'jet500.dll', 'jobexec.dll', 'jscript.dll', 'jsproxy.dll', 'kbd101.dll', 'kbd101a.dll', 'kbd101b.dll', 'kbd101c.dll', 'kbd103.dll', 'kbd106.dll', 'kbd106n.dll', 'kbda1.dll', 'kbda2.dll', 'kbda3.dll', 'kbdarme.dll', 'kbdarmw.dll', 'kbdax2.dll', 'kbdaze.dll', 'kbdazel.dll', 'kbdbe.dll', 'kbdbene.dll', 'kbdbhc.dll', 'kbdblr.dll', 'kbdbr.dll', 'kbdbu.dll', 'kbdca.dll', 'kbdcan.dll', 'kbdcr.dll', 'kbdcz.dll', 'kbdcz1.dll', 'kbdcz2.dll', 'kbdda.dll', 'kbddiv1.dll', 'kbddiv2.dll', 'kbddv.dll', 'kbdes.dll', 'kbdest.dll', 'kbdfa.dll', 'kbdfc.dll', 'kbdfi.dll', 'kbdfi1.dll', 'kbdfo.dll', 'kbdfr.dll', 'kbdgae.dll', 'kbdgeo.dll', 'kbdgkl.dll', 'kbdgr.dll', 'kbdgr1.dll', 'kbdhe.dll', 'kbdhe220.dll', 'kbdhe319.dll', 'kbdheb.dll', 'kbdhela2.dll', 'kbdhela3.dll', 'kbdhept.dll', 'kbdhu.dll', 'kbdhu1.dll', 'kbdibm02.dll', 'kbdic.dll', 'kbdinbe1.dll', 'kbdinben.dll', 'kbdindev.dll', 'kbdinguj.dll', 'kbdinhin.dll', 'kbdinkan.dll', 'kbdinmal.dll', 'kbdinmar.dll', 'kbdinpun.dll', 'kbdintam.dll', 'kbdintel.dll', 'kbdir.dll', 'kbdit.dll', 'kbdit142.dll', 'kbdiultn.dll', 'kbdjpn.dll', 'kbdkaz.dll', 'kbdkor.dll', 'kbdkyr.dll', 'kbdla.dll', 'kbdlk41a.dll', 'kbdlk41j.dll', 'kbdlt.dll', 'kbdlt1.dll', 'kbdlv.dll', 'kbdlv1.dll', 'kbdmac.dll', 'kbdmaori.dll', 'kbdmlt47.dll', 'kbdmlt48.dll', 'kbdmon.dll', 'kbdne.dll', 'kbdnec.dll', 'kbdnec95.dll', 'kbdnecAT.dll', 'kbdnecNT.dll', 'kbdnepr.dll', 'kbdno.dll', 'kbdno1.dll', 'kbdpash.dll', 'kbdpl.dll', 'kbdpl1.dll', 'kbdpo.dll', 'kbdro.dll', 'kbdru.dll', 'kbdru1.dll', 'kbdsf.dll', 'kbdsg.dll', 'kbdsl.dll', 'kbdsl1.dll', 'kbdsmsfi.dll', 'kbdsmsno.dll', 'kbdsp.dll', 'kbdsw.dll', 'kbdsyr1.dll', 'kbdsyr2.dll', 'kbdtat.dll', 'kbdth0.dll', 'kbdth1.dll', 'kbdth2.dll', 'kbdth3.dll', 'kbdtuf.dll', 'kbdtuq.dll', 'kbduk.dll', 'kbdukx.dll', 'kbdur.dll', 'kbdurdu.dll', 'kbdus.dll', 'kbdusa.dll', 'kbdusl.dll', 'kbdusr.dll', 'kbdusx.dll', 'kbduzb.dll', 'kbdvntc.dll', 'kbdycc.dll', 'kbdycl.dll', 'kd1394.dll', 'kdcom.dll', 'kerberos.dll', 'kernel32.dll', 'keymgr.dll', 'kmsvc.dll', 'korwbrkr.dll', 'ksuser.dll', 'l2gpstore.dll', 'langwrbk.dll', 'laprxy.dll', 'licdll.dll', 'licmgr10.dll', 'licwmi.dll', 'linkinfo.dll', 'lmhsvc.dll', 'lmrt.dll', 'loadperf.dll', 'localsec.dll', 'localspl.dll', 'localui.dll', 'loghours.dll', 'lpk.dll', 'lprhelp.dll', 'lprmonui.dll', 'lsasrv.dll', 'lz32.dll', 'mag_hook.dll', 'mapi32.dll', 'mapistub.dll', 'mcastmib.dll', 'mcd32.dll', 'mcdsrv32.dll', 'mchgrcoi.dll', 'mciavi32.dll', 'mcicda.dll', 'mciole32.dll', 'mciqtz32.dll', 'mciseq.dll', 'mciwave.dll', 'mdhcp.dll', 'mdminst.dll', 'mf3216.dll', 'mfc40.dll', 'mfc40u.dll', 'mfc42.dll', 'mfc42u.dll', 'mfcsubs.dll', 'mgmtapi.dll', 'managementconsole.dll', 'midimap.dll', 'miglibnt.dll', 'mimefilt.dll', 'mlang.dll', 'mll_hp.dll', 'mll_mtf.dll', 'mll_qic.dll', 'mmcbase.dll', 'mmcex.dll', 'mmcfxcommon.dll', 'mmcndmgr.dll', 'mmcshext.dll', 'mmdrv.dll', 'mmfutil.dll', 'mmutilse.dll', 'mnmdd.dll', 'mobsync.dll', 'modemui.dll', 'modex.dll', 'moricons.dll', 'mp43dmod.dll', 'mp4sdmod.dll', 'mpg4dmod.dll', 'mpr.dll', 'mprapi.dll', 'mprddm.dll', 'mprdim.dll', 'mprmsg.dll', 'mprui.dll', 'mqad.dll', 'mqcertui.dll', 'mqdscli.dll', 'mqgentr.dll', 'mqise.dll', 'mqlogmgr.dll', 'mqoa.dll', 'mqperf.dll', 'mqqm.dll', 'mqrt.dll', 'mqrtdep.dll', 'mqsec.dll', 'mqsnap.dll', 'mqtrig.dll', 'mqupgrd.dll', 'mqutil.dll', 'msaatext.dll', 'msacm32.dll', 'msafd.dll', 'msapsspc.dll', 'msasn1.dll', 'msaudite.dll', 'mscat32.dll', 'mscms.dll', 'msconf.dll', 'mscpx32r.dll', 'mscpxl32.dll', 'msctf.dll', 'msctfp.dll', 'msdadiag.dll', 'msdart.dll', 'msdbg2.dll', 'msdmo.dll', 'msdtclog.dll', 'msdtcprx.dll', 'msdtctm.dll', 'msdtcuiu.dll', 'msdxmlc.dll', 'msencode.dll', 'msexch40.dll', 'msexcl40.dll', 'msfeeds.dll', 'msfeedsbs.dll', 'msftedit.dll', 'msgina.dll', 'msgsvc.dll', 'mshtml.dll', 'mshtmled.dll', 'mshtmler.dll', 'msi.dll', 'msident.dll', 'msidle.dll', 'msidntld.dll', 'msieftp.dll', 'msihnd.dll', 'msimg32.dll', 'msimsg.dll', 'msimtf.dll', 'msir3jp.dll', 'msisip.dll', 'msjet40.dll', 'msjetoledb40.dll', 'msjint40.dll', 'msjter40.dll', 'msjtes40.dll', 'mslbui.dll', 'msls31.dll', 'msltus40.dll', 'msnetobj.dll', 'msnsspc.dll', 'msobjs.dll', 'msoeacct.dll', 'msoert2.dll', 'msorc32r.dll', 'msorcl32.dll', 'mspatcha.dll', 'mspbde40.dll', 'mspmsnsv.dll', 'mspmsp.dll', 'msports.dll', 'msprivs.dll', 'msr2c.dll', 'msr2cenu.dll', 'msratelc.dll', 'msrating.dll', 'msrclr40.dll', 'msrd2x40.dll', 'msrd3x40.dll', 'msrecr40.dll', 'msrepl40.dll', 'msrle32.dll', 'mssap.dll', 'msscp.dll', 'mssha.dll', 'msshavmsg.dll', 'mssign32.dll', 'mssip32.dll', 'msswch.dll', 'mstask.dll', 'mstext40.dll', 'mstime.dll', 'mstlsapi.dll', 'mstscax.dll', 'msutb.dll', 'msv1_0.dll', 'msvbvm50.dll', 'msvbvm60.dll', 'msvcirt.dll', 'msvcp50.dll', 'msvcp60.dll', 'msvcrt.dll', 'msvcrt20.dll', 'msvcrt40.dll', 'msvcrt.dll', 'msvfw32.dll', 'msvidc32.dll', 'msvidctl.dll', 'msw3prt.dll', 'mswdat10.dll', 'mswebdvd.dll', 'mswmdm.dll', 'mswsock.dll', 'mswstr10.dll', 'msxbde40.dll', 'msxml.dll', 'msxml2.dll', 'msxml2r.dll', 'msxml3.dll', 'msxml3r.dll', 'msxml6.dll', 'msxml6r.dll', 'msxmlr.dll', 'msyuv.dll', 'mtxclu.dll', 'mtxdm.dll', 'mtxex.dll', 'mtxlegih.dll', 'mtxoci.dll', 'mycomput.dll', 'mydocs.dll', 'napipsec.dll', 'napmontr.dll', 'narrhook.dll', 'ncobjapi.dll', 'ncxpnt.dll', 'nddeapi.dll', 'nddenb32.dll', 'netapi32.dll', 'netcfgx.dll', 'netevent.dll', 'neth.dll', 'netid.dll', 'netlogon.dll', 'netman.dll', 'netmsg.dll', 'netplwiz.dll', 'netrap.dll', 'netshell.dll', 'netui0.dll', 'netui1.dll', 'netui2.dll', 'newdev.dll', 'nlhtml.dll', 'nlsdl.dll', 'nmevtmsg.dll', 'nmmkcert.dll', 'normaliz.dll', 'npptools.dll', 'ntdll.dll', 'ntdsapi.dll', 'ntdsbcli.dll', 'ntlanman.dll', 'ntlanui.dll', 'ntlanui2.dll', 'ntlsapi.dll', 'ntmarta.dll', 'ntmsapi.dll', 'ntmsdba.dll', 'ntmsevt.dll', 'ntmsmgr.dll', 'ntmssvc.dll', 'ntprint.dll', 'ntsdexts.dll', 'ntshrui.dll', 'ntvdmd.dll', 'nwapi16.dll', 'nwapi32.dll', 'nwcfg.dll', 'nwevent.dll', 'nwprovau.dll', 'nwwks.dll', 'oakley.dll', 'objsel.dll', 'occache.dll', 'ocmanage.dll', 'odbc32.dll', 'odbc32gt.dll', 'odbcbcp.dll', 'odbcconf.dll', 'odbccp32.dll', 'odbccr32.dll', 'odbccu32.dll', 'odbcint.dll', 'odbcji32.dll', 'odbcjt32.dll', 'odbcp32r.dll', 'odbctrac.dll', 'oddbse32.dll', 'odexl32.dll', 'odfox32.dll', 'odpdx32.dll', 'odtext32.dll', 'offfilt.dll', 'ole32.dll', 'oleacc.dll', 'oleaccrc.dll', 'oleaut32.dll', 'olecli32.dll', 'olecnv32.dll', 'oledlg.dll', 'oleprn.dll', 'olepro32.dll', 'olesvr32.dll', 'olethk32.dll', 'onex.dll', 'opengl32.dll', 'osuninst.dll', 'p2p.dll', 'p2pgasvc.dll', 'p2pgraph.dll', 'p2pnetsh.dll', 'p2psvc.dll', 'panmap.dll', 'pautoenr.dll', 'pdh.dll', 'perfctrs.dll', 'perfdisk.dll', 'perfnet.dll', 'perfnw.dll', 'perfos.dll', 'perfproc.dll', 'perfts.dll', 'photometadatahandler.dll', 'photowiz.dll', 'pid.dll', 'pidgen.dll', 'pifmgr.dll', 'pjlmon.dll', 'plustab.dll', 'pngfilt.dll', 'pnrpnsp.dll', 'polstore.dll', 'powrprof.dll', 'prflbmsg.dll', 'printui.dll', 'profmap.dll', 'psapi.dll', 'psbase.dll', 'pschdprf.dll', 'psnppagn.dll', 'pstorec.dll', 'pstorsvc.dll', 'qagent.dll', 'qagentrt.dll', 'qasf.dll', 'qcap.dll', 'qcliprov.dll', 'qdv.dll', 'qdvd.dll', 'qedit.dll', 'qedwipes.dll', 'qmgr.dll', 'qmgrprxy.dll', 'qosname.dll', 'quartz.dll', 'query.dll', 'qutil.dll', 'racpldlg.dll', 'rasadhlp.dll', 'rasapi32.dll', 'rasauto.dll', 'raschap.dll', 'rasctrs.dll', 'rasdlg.dll', 'rasman.dll', 'rasmans.dll', 'rasmontr.dll', 'rasmxs.dll', 'rasppp.dll', 'rasqec.dll', 'rasrad.dll', 'rassapi.dll', 'rasser.dll', 'rastapi.dll', 'rastls.dll', 'rcbdyctl.dll', 'rdchost.dll', 'rdpcfgex.dll', 'rdpdd.dll', 'rdpsnd.dll', 'rdpwsx.dll', 'regapi.dll', 'regsvc.dll', 'regwizc.dll', 'remotepg.dll', 'rend.dll', 'resutils.dll', 'rhttpaa.dll', 'riched20.dll', 'riched32.dll', 'rnr20.dll', 'routetab.dll', 'rpcns4.dll', 'rpcrt4.dll', 'rpcss.dll', 'rsaenh.dll', 'rsfsaps.dll', 'rshx32.dll', 'rsmps.dll', 'rsvpmsg.dll', 'rsvpperf.dll', 'rsvpsp.dll', 'rtipxmib.dll', 'rtm.dll', 'rtutils.dll', 'rwnh.dll', 's3legacy.dll', 'safrcdlg.dll', 'safrdm.dll', 'safrslv.dll', 'samlib.dll', 'samsrv.dll', 'sbe.dll', 'sbeio.dll', 'scarddlg.dll', 'scardssp.dll', 'sccbase.dll', 'sccsccp.dll', 'scecli.dll', 'scesrv.dll', 'schannel.dll', 'schedsvc.dll', 'sclgntfy.dll', 'scredir.dll', 'scrobj.dll', 'scrrun.dll', 'sdhcinst.dll', 'sdpblb.dll', 'seclogon.dll', 'secur32.dll', 'security.dll', 'sendcmsg.dll', 'sendmail.dll', 'sens.dll', 'sensapi.dll', 'senscfg.dll', 'serialui.dll', 'servdeps.dll', 'serwvdrv.dll', 'setupapi.dll', 'setupdll.dll', 'sfc.dll', 'sfc_os.dll', 'sfcfiles.dll', 'sfmapi.dll', 'shdoclc.dll', 'shdocvw.dll', 'shell32.dll', 'shellstyle.dll', 'shfolder.dll', 'shgina.dll', 'shimeng.dll', 'shimgvw.dll', 'shlwapi.dll', 'shmedia.dll', 'shscrap.dll', 'shsvcs.dll', 'sigtab.dll', 'sisbkup.dll', 'skdll.dll', 'slayerxp.dll', 'smlogcfg.dll', 'smtpapi.dll', 'snmpapi.dll', 'snmpsnap.dll', 'softpub.dll', 'spmsg.dll', 'spoolss.dll', 'sqlsrv32.dll', 'sqlunirl.dll', 'sqlwid.dll', 'sqlwoa.dll', 'srclient.dll', 'srrstr.dll', 'srsvc.dll', 'srvsvc.dll', 'ssdpapi.dll', 'ssdpsrv.dll', 'stclient.dll', 'sti.dll', 'sti_ci.dll', 'stobject.dll', 'storprop.dll', 'streamci.dll', 'strmdll.dll', 'strmfilt.dll', 'svcpack.dll', 'swprv.dll', 'sxs.dll', 'synceng.dll', 'syncui.dll', 'sysinv.dll', 'syssetup.dll', 'Thawbrkr.dll', 't2embed.dll', 'tapi3.dll', 'tapi32.dll', 'tapiperf.dll', 'tapisrv.dll', 'tapiui.dll', 'tcpmib.dll', 'tcpmon.dll', 'tcpmonui.dll', 'termmgr.dll', 'termsrv.dll', 'themeui.dll', 'tlntsvrp.dll', 'traffic.dll', 'trkwks.dll', 'tsappcmp.dll', 'tsbyuv.dll', 'tscfgwmi.dll', 'tsddd.dll', 'tsgqec.dll', 'tspkg.dll', 'twext.dll', 'txflog.dll', 'udhisapi.dll', 'ufat.dll', 'ulib.dll', 'umandlg.dll', 'umdmxfrm.dll', 'umpnpmgr.dll', 'uniime.dll', 'unimdmat.dll', 'uniplat.dll', 'untfs.dll', 'upnp.dll', 'upnphost.dll', 'upnpui.dll', 'ureg.dll', 'url.dll', 'urlmon.dll', 'usbmon.dll', 'user32.dll', 'userenv.dll', 'usp10.dll', 'utildll.dll', 'uxtheme.dll', 'vbajet32.dll', 'vbscript.dll', 'vcdex.dll', 'vdmdbg.dll', 'verifier.dll', 'version.dll', 'vfpodbc.dll', 'vga.dll', 'vga256.dll', 'vga64k.dll', 'vjoy.dll', 'vmsrvc.dll', 's3.dll', 'vss_ps.dll', 'vssapi.dll', 'vwipxspx.dll', 'w32time.dll', 'w32topl.dll', 'w3ssl.dll', 'wavemsp.dll', 'wdigest.dll', 'webcheck.dll', 'webclnt.dll', 'webhits.dll', 'webvw.dll', 'wiadefui.dll', 'wiadss.dll', 'wiascr.dll', 'wiaservc.dll', 'wiashext.dll', 'wiavideo.dll', 'wiavusd.dll', 'win32spl.dll', 'winbrand.dll', 'windowscodecs.dll', 'windowscodecsext.dll', 'winfax.dll', 'winhttp.dll', 'wininet.dll', 'winipsec.dll', 'winmm.dll', 'winntbbu.dll', 'winrnr.dll', 'winscard.dll', 'winshfhc.dll', 'winsrv.dll', 'winsta.dll', 'winstrm.dll', 'wintrust.dll', 'wkssvc.dll', 'wlanapi.dll', 'wldap32.dll', 'wlnotify.dll', 'wmadmod.dll', 'wmadmoe.dll', 'wmasf.dll', 'wmdmlog.dll', 'wmdmps.dll', 'wmerrenu.dll', 'wmerror.dll', 'wmi.dll', 'wmidx.dll', 'wmiprop.dll', 'wmiscmgr.dll', 'wmnetmgr.dll', 'wmp.dll', 'wmpasf.dll', 'wmpcd.dll', 'wmpcore.dll', 'wmpdxm.dll', 'wmphoto.dll', 'wmploc.dll', 'wmpshell.dll', 'wmpui.dll', 'wmsdmod.dll', 'wmsdmoe.dll', 'wmsdmoe2.dll', 'wmspdmod.dll', 'wmspdmoe.dll', 'wmstream.dll', 'wmvcore.dll', 'wmvdmod.dll', 'wmvdmoe2.dll', 'wow32.dll', 'wowfax.dll', 'wowfaxui.dll', 'ws2_32.dll', 'ws2help.dll', 'wscsvc.dll', 'wsecedit.dll', 'wshatm.dll', 'wshbth.dll', 'wshcon.dll', 'wshext.dll', 'wship6.dll', 'wshisn.dll', 'wshnetbs.dll', 'wshrm.dll', 'wshtcpip.dll', 'wsnmp32.dll', 'wsock32.dll', 'wstdecod.dll', 'wtsapi32.dll', 'wuapi.dll', 'wuaueng.dll', 'wuaueng1.dll', 'wuauserv.dll', 'wucltui.dll', 'wups.dll', 'wuweb.dll', 'wzcdlg.dll', 'wzcsapi.dll', 'wzcsvc.dll', 'xactsrv.dll', 'xenroll.dll', 'xmllite.dll', 'xmlprov.dll', 'xmlprovi.dll', 'xolehlp.dll', 'xpob2res.dll', 'xpsp1res.dll', 'xpsp2res.dll', 'xpsp3res.dll', 'zipfldr.dll', 'kernelbase.dll']


# to save time custom dict, just add what sample will load
custom_dlls = ['kernel32.dll', 'comctl32.dll', 'advapi32.dll', 'comdlg32.dll',
		'gdi32.dll',    'msvcrt.dll',   'netapi32.dll', 'ntdll.dll',
		'ntoskrnl.exe', 'oleaut32.dll', 'psapi.dll',    'shell32.dll',
		'shlwapi.dll',  'srsvc.dll',    'urlmon.dll',   'user32.dll',
		'winhttp.dll',  'wininet.dll',  'ws2_32.dll',   'wship6.dll',
		'advpack.dll', 'kernelbase.dll' 'cryptbase.dll', 'crypt32.dll',
		'cryptsp.dll'
		]
			
	


def get_functions(dll_path):
	pe = pefile.PE(dll_path)
	if ((not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')) or (pe.DIRECTORY_ENTRY_EXPORT is None)):
		print "[*] No exports for %s" % dll_path
		return []
	else:
		expname = []
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			if exp.name:
				expname.append(exp.name)
		return expname


win_path = os.environ['WINDIR']
system32_path = os.path.join(win_path, "system32")

data = {}
for dll in custom_dlls:
	dll_path = os.path.join(system32_path, dll)
	dll_name = dll.split(".")[0].lower()
	if os.path.isfile(dll_path):
		for f in get_functions(dll_path):
			f_name = re.sub(r'\W+', '_', f)
			name = dll_name + "_" + f_name
			data[hash_function1(f)] = name
		print "[+] Generated functions for %s" % dll_path
	else:
		print "[*] File not found: %s" % dll_path

f = open("output.json", 'w')
f.write(json.dumps(data))
f.close

print "[+] Wrote output.json"
