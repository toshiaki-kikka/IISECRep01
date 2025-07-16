################################################################################
# File      :   OSSVulHeatMap.py
# Purpose   :   複数のCVEファイルを読み込んで一つのDataFrameにconcatしHeatmapを作成する
#
# Date      :   2025-06-13(Fri)
# Copyright (c) 2025 toshiaki kikka
#
# This program is licensed under the MIT License. See LICENSE file in the project root.
#
# ----------------------------------------------------------------------------------------------
# This program uses data from the Common Vulnerabilities and Exposures (CVE(®) list.
# (c) 1997-2025 The MITRE Corporation.
# Licensed under the CVER Terms of Use.
# https://www.cve.org/Legal/TermsOfUse
#
# Permission is hereby granted, free of charge, to use, reproduce, modify, and distribute
# the CVE data used in this program, provided that this copyright notice and license text
# are included in all copies or substantial portions of the software.
#
# THE DATA IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE DATA OR THE USE OR OTHER
# DEALINGS IN THE DATA.
# ----------------------------------------------------------------------------------------------

from matplotlib.lines import Line2D
import json, re
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib
import mplcursors
from dataclasses import dataclass
from pathlib import Path

################################################################################
#
# OSS名, CVE値、Published Date, CVSS値を含むDataFrameを作成する。
#
# ###############################################################################
# DataFrameは https://www.cvedetails.com/から
# コピペしたデータをファイルにそののまま保存する。FormatはUTF8. 
# Fileはこのpythonファイルのあるフォルダーのサブフォルダー CVEFilesに配置する。
# そのファイルを読んでCVSS値をプロットする。
# fileformatは以下のようなTab区切りのFormat
# 例)
# https://www.cvedetails.com/vulnerability-list/vendor_id-45/Apache.html
# のページにおいて右上の[Copy]をクリック、コピーした内容を CVE_HTTPD_01.txtとして保存する。
# Pageが複数ある場合は次のPageを表示, Copyし、別ファイル名(例: CVE_HTTPD_02.txt)として保存する 
#
# 以下はファイルの例
# CVE   Published       Last Update     Max CVSS Base Score     EPSS Score      CISA KEV Added  Public Exploit Exists   Summary
# CVE-2024-40898        2024-07-18      2024-08-08      9.1     0.06%                   
# CVE-2024-40725        2024-07-18      2025-03-14      5.3     23.96%  
#    :
#

@dataclass
class OssCVEFiles:
    name_oss:   str
    name_file:  str

file_list = [
    # ./CVEFiles下にあるファイル名に対応するOSS/OS名とファイル名をペアとして定義する
    # CVE_WinSVR2019_CVSS9_0*.txt(Windows Serer 2019でCVSSが9以上のもののリスト
    #
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_01.txt'),    
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_02.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_03.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_04.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_05.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_06.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_07.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_08.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_09.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_10.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_11.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_12.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_13.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2019_CVSS9_14.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2016_CVSS9_15.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2016_CVSS9_16.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2016_CVSS9_17.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2012_CVSS9_14.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2012_CVSS9_15.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2012_CVSS9_16.txt'),
    OssCVEFiles('WinSVR(9≦CVSS)',       'CVE_WinSVR2012_CVSS9_17.txt'),

    # OpenJDKのCVE
    OssCVEFiles('JDK',          'CVE_OpenJDK_01.txt'),
    OssCVEFiles('JDK',          'CVE_OpenJDK_02.txt'),
    OssCVEFiles('JDK',          'CVE_OpenJDK_03.txt'),
    OssCVEFiles('JDK',          'CVE_OpenJDK_04.txt'),

    # Apache httpdとそれが利用しているOSSのCVEファイル
    OssCVEFiles('httpd',        'CVE_HTTPD_00_20250613.txt'),  #2025-06-13(Fri) Added
    OssCVEFiles('httpd',        'CVE_HTTPD_01.txt'),  
    OssCVEFiles('httpd',        'CVE_HTTPD_02.txt'),
    OssCVEFiles('httpd',        'CVE_HTTPD_03.txt'),
    OssCVEFiles('httpd',        'CVE_HTTPD_04.txt'),
    OssCVEFiles('httpd',        'CVE_HTTPD_05.txt'),
    OssCVEFiles('OpenSSL',      'CVE_HTTPD_OPENSSL01.txt'),
    OssCVEFiles('OpenSSL',      'CVE_HTTPD_OPENSSL02.txt'),
    OssCVEFiles('OpenSSL',      'CVE_HTTPD_OPENSSL03.txt'),
    OssCVEFiles('OpenSSL',      'CVE_HTTPD_OPENSSL04.txt'),
    OssCVEFiles('OpenSSL',      'CVE_HTTPD_OPENSSL05.txt'),
    OssCVEFiles('OpenSSL',      'CVE_HTTPD_OPENSSL06.txt'),
    OssCVEFiles('PCRE',         'CVE_HTTPD_PCRE_01.txt'),
    OssCVEFiles('PCRE',         'CVE_HTTPD_PCRE_02.txt'),
    OssCVEFiles('PCRE',         'CVE_HTTPD_PCRE_03.txt'),
    OssCVEFiles('ZLib',         'CVE_HTTPD_ZLIB_01.txt'),

    # Apache tomcatとそれが利用しているOSSのCVEファイル
    OssCVEFiles('tomcat',       'CVE_TOMCAT_00_20250613.txt'),  #2025-06-13(Fri) Added
    OssCVEFiles('tomcat',       'CVE_TOMCAT_01.txt'),
    OssCVEFiles('tomcat',       'CVE_TOMCAT_02.txt'),
    OssCVEFiles('tomcat',       'CVE_TOMCAT_03.txt'),
    OssCVEFiles('tomcat',       'CVE_TOMCAT_04.txt'),
    OssCVEFiles('tomcat',       'CVE_TOMCAT_05.txt'),
    OssCVEFiles('Jasper',       'CVE_TOMCAT_JASPER_01.txt'),
    OssCVEFiles('Jasper',       'CVE_TOMCAT_JASPER_02.txt'),
    OssCVEFiles('Jasper',       'CVE_TOMCAT_JASPER_03.txt'),
    OssCVEFiles('Jasper',       'CVE_TOMCAT_JASPER_04.txt'),
    OssCVEFiles('Websockets',   'CVE_TOMCAT_Websockets_01.txt'),

    # Apache solrとそれが利用しているOSSのCVEファイル
    OssCVEFiles('solr',         'CVE_SOLR_01.txt'       ),
    OssCVEFiles('solr',         'CVE_SOLR_02.txt'       ),
    OssCVEFiles('J-Databind',   'CVE_SOLR_JacksonDatabind_01.txt'),
    OssCVEFiles('J-Databind',   'CVE_SOLR_JacksonDatabind_02.txt'),
    OssCVEFiles('J-Databind',   'CVE_SOLR_JacksonDatabind_03.txt'),
    OssCVEFiles('Jetty',        'CVE_SOLR_Jetty_01.txt'    ),
    OssCVEFiles('Jetty',        'CVE_SOLR_Jetty_02.txt'    ),
    OssCVEFiles('Log4j',        'CVE_SOLR_Log4j_01.txt'    ),
    OssCVEFiles('OpenNLP',      'CVE_SOLR_Opennlp_01.txt'  ),
    OssCVEFiles('Tika',         'CVE_SOLR_Tika_01.txt'     ),
    OssCVEFiles('Zookeeper',    'CVE_SOLR_Zookeeper_01.txt'),
]    

df = []
dummyData = [
    ['CVE-2025-0101', '2015-01-01', '2015-01-01', 0.0, ''],
]
dummyDf = pd.DataFrame(dummyData,
                       columns=['CVE',
                                'Published',
                                'Last Update',
                                'Max CVSS Base Score',
                                'OSS'])
df.append(dummyDf)

# 作りたいDataFrameは以下のようなもの
#   OSS(str)     CVE(str)           Published(str)      CVSS(float)
#   ---------------------------------------------------------------
#   'httpd'     'CVE-2024-13176'    '2025-01-20'        4.1
#   'httpd'     'CVE-2024-12797'    '2025-02-11'        6.3
#   'httpd'     'CVE-2024-9143'     '2024-10-16'        4.3


for file in file_list:
    #print(file.name_file)
    fname = Path("CVEFiles") / file.name_file
    #print(fname)

    temp = pd.read_csv(fname, sep='\t', encoding='utf-8', header=0)
    
    #ファイルの一行目のheaderを除外する
    temp = temp[temp['CVE'] != 'CVE']
    temp = temp[['CVE', 'Published', 'Max CVSS Base Score']]
    temp['OSS'] = file.name_oss
    df.append(temp)

#print(df) 

df = pd.concat(df, ignore_index=True)

# ------------------------------------------------
# CVE-2015以上のものをprotするためCVE-2014以下を削除
# 年の抽出と数値化

df['year'] = df['CVE'].str.extract(r'CVE-(\d{4})')[0].astype(int)
#print("debug01")
# 2015年未満を削除（2014年以前を除外）
df = df[df['year'] >= 2015].drop(columns='year')
#print("debug02")


#  列名を変更（"Max CVSS Base Score" → "CVSS"）
df = df.rename(columns={'Max CVSS Base Score': 'CVSS'})
df['CVSS']      = pd.to_numeric(df['CVSS'], errors='coerce')
df["Published"] = pd.to_datetime(df["Published"])


# CVSSに応じた色付け
def cvss_color(score):
    if score == 0:         return "white"
    elif score < 1:        return "#00C400"
    elif score < 2:        return "#00E020"
    elif score < 3:        return "#00F000"    
    elif score < 4:        return "#D1FF00"    #薄いグリーン
    elif score < 5:        return "#ffe000"
    elif score < 6:        return "#ffcc00"
    elif score < 7:        return "#ffbc10"
    elif score < 8:        return "#ff9c20"
    elif score < 9:        return "#ff8000"
    else:                  return "#ff0000"

df["Color"] = df["CVSS"].apply(cvss_color)

plt.figure(figsize=(10, 6))

scatter = plt.scatter(df["Published"], df["OSS"], c=df["Color"], s=50)

plt.title("CVE Timeline (2015-2025) by OSS with CVSS Color Coding")
plt.xlabel("CVE Published Date")
plt.ylabel("OS-Java-OSS")
#plt.yticks(list(oss_positions.values()), list(oss_positions.keys()))

# 年ごとの目盛りを追加
ax = plt.gca()
ax.xaxis.set_major_locator(mdates.YearLocator(1))  # 1年ごとの目盛り
ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y'))  # 西暦表示

plt.grid(True, axis='x', linestyle='--', alpha=0.5)
plt.grid(True, axis='y', linestyle='--', alpha=0.5)

#2025-04-19(Sat)
#凡例をつける
legend_elements = [
Line2D([0],[0],marker='o',color='w',label='9 ≤ CVSS)',    markerfacecolor='#ff0000',markersize=8),
Line2D([0],[0],marker='o',color='w',label='8 ≤ CVSS < 9)',markerfacecolor='#ff8000',markersize=8),
Line2D([0],[0],marker='o',color='w',label='7 ≤ CVSS < 8)',markerfacecolor='#ff9c20',markersize=8),
Line2D([0],[0],marker='o',color='w',label='6 ≤ CVSS < 7)',markerfacecolor='#ffbc10',markersize=8),
Line2D([0],[0],marker='o',color='w',label='5 ≤ CVSS < 6)',markerfacecolor='#ffcc00',markersize=8),
Line2D([0],[0],marker='o',color='w',label='4 ≤ CVSS < 5)',markerfacecolor='#ffe000',markersize=8),
Line2D([0],[0],marker='o',color='w',label='3 ≤ CVSS < 4)',markerfacecolor='#D1FF00',markersize=8),
Line2D([0],[0],marker='o',color='w',label='2 ≤ CVSS < 3)',markerfacecolor='#00F000',markersize=8),
Line2D([0],[0],marker='o',color='w',label='1 ≤ CVSS < 2)',markerfacecolor='#00E020',markersize=8),
Line2D([0],[0],marker='o',color='w',label='0 ≤ CVSS < 1)',markerfacecolor='#00C400',markersize=8)
]

#左上に凡例を表示
plt.legend(handles=legend_elements, title="CVSS Risk Level", loc='upper left')

#ホバーで情報表示
#左詰めでホバーを表示
mplcursors.cursor(scatter).connect(
    "add", 
    lambda sel: (
        sel.annotation.set_text(
            f"CVE: {df.iloc[sel.index]['CVE']}\nPublished: {df.iloc[sel.index]['Published'].date()}\nCVSS: {df.iloc[sel.index]['CVSS']}"
        ),
        sel.annotation.set_ha("left")
    )
)

plt.tight_layout()
#print(matplotlib.get_backend())
plt.show()
