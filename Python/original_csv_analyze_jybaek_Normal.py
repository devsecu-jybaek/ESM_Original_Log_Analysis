import csv
import re
import pandas as pd
import tkinter as tk
from tkinter import filedialog

#최종 수정일자: 2024-01-31

# CSV 파일 경로 지정(기존코드)
window = tk.Tk()
window.withdraw() # withdraw :기본창을 보이지 않게 하는 함수
window.file = filedialog.askopenfile()
window.mainloop

# CSV 파일 불러오기
df_O = pd.read_csv(window.file.name, encoding='CP949')
# print(df_O)


log_df = pd.DataFrame(df_O)

# 공격명 및 로그 데이터 추출 함수 정의
def extract_log_info(원본로그):
    # attack_name_match = re.search(r'\[WEBFRONT/0x0072F001\] (.*?) -', log)
    attack_name_match = re.search(r"\] (.*?)\(", 원본로그)
    attack_name = attack_name_match.group(1) if attack_name_match else None
    
    log_entries = re.findall(r'(\w+)=["\'](.*?)["\']', 원본로그)
    
    columns = ['attack_nm'] + [entry[0] for entry in log_entries]
    values = [attack_name] + [entry[1] for entry in log_entries]
    
    return columns, values

# 데이터 프레임 생성
columns, values = extract_log_info(log_df['원본로그'][0])
df = pd.DataFrame([values], columns=columns)





















# col_nm_0 = '원본로그'
# log=df_O.loc[df_O[col_nm_0]]

# # Extract the part between "]" and "("
# attack_name = re.search(r"\] (.*?)\(", log).group(1).strip()
# data = re.findall(r'(\w+)=["\'](.*?)["\']', log)
# columns = ['attack_nm'] + [item[0] for item in data]
# values = [attack_name] + [item[1] for item in data]
# df = pd.DataFrame([values], columns=columns)
print(df)

# 분류할 열 지정
col_nm_1 = 'src_ip'
col_nm_2 = 'dest_ip'
# col_nm_2_2 = '장비IP'
col_nm_3 = 'attack_nm'
# col_nm_4 = '출발지 국가'
col_nm_5 = 'sig_warning'


# #위험도 카테고리 결측치 및 이상치 값치환
# df.loc[df[col_nm_5] == "1", col_nm_5] = 'High'
# df.loc[df[col_nm_5] == "2", col_nm_5] = 'Middle'
# df.loc[df[col_nm_5].isnull(), col_nm_5] = 'Info'


# 항목별 데이터 조회 후 프레임화(일반보고서)
top_src_ip_20 = df.loc[:,col_nm_1].value_counts(dropna = False).head(20)
top_dstn_ip_20 = df.loc[:,[col_nm_2]].value_counts(dropna = False).head(20)
top_attack_20 = df.loc[:,col_nm_3].value_counts(dropna = False).head(20)
# top_src_country_20 = df.loc[:,col_nm_4].value_counts(dropna = False).head(20)
top_sev_level_20 = df.loc[:,col_nm_5].value_counts(dropna = False).head(20)

# 파일명에 데이터갯수를 포함시키기 위한 변수 설정
data_number = df.loc[:,col_nm_5].size

# 조회된 데이터를 기준으로 새로운 프레임 생성 후 인덱스 초기화
total_1 = pd.DataFrame(top_src_ip_20)
total_1.reset_index(drop =False, inplace = True)

total_2 = pd.DataFrame(top_dstn_ip_20)
total_2.reset_index(drop =False, inplace = True)

total_3 = pd.DataFrame(top_attack_20)
total_3.reset_index(drop =False, inplace = True)

# total_4 = pd.DataFrame(top_src_country_20)
# total_4.reset_index(drop =False, inplace = True)

total_5 = pd.DataFrame(top_sev_level_20)
total_5.reset_index(drop =False, inplace = True)

#데이터프레임에서 Count 열의 데이터에 천단위 구분기호(,) 일괄 적용 
# total_dfs = []
# for i in range(1, 6):
#     df_name = f'total_{i}'
#     df_n = globals()[df_name]
#     total_dfs.append(df_n)

# for df_n in total_dfs:
#     df_n['count'] = df_n['count'].apply(lambda int_num : '{:,}'.format(int_num))


# # 데이터 통합용 목적지 IP, count 틀만 존재하는 빈 프레임 생성
# total_2_2 = pd.DataFrame(columns=['목적지IP','count'])

# 생성된 프레임들을 병합
total = pd.concat([total_1,total_2,total_3,total_5],axis=1)

# 각 프레임 구분을 위해 기본 인덱스 이름 변경 및 빈열 & 인덱스 중복 추가
idx_default= [f"{i}위" for i in range(1, 21)]

total.index = idx_default
total.insert(2, "", "", allow_duplicates=True)
total.insert(3, "", idx_default, allow_duplicates=True)
total.insert(6, "", "", allow_duplicates=True)
total.insert(7, "", idx_default, allow_duplicates=True)
total.insert(10, "", "", allow_duplicates=True)
total.insert(11, "", idx_default, allow_duplicates=True)



log_nm = str(window.file.name).split('/') #기본파일명

#파일명변환과정
log_fl = log_nm[-1].split('LOG')

log_file_name = log_fl[0]

free_name = re.sub(r"[^a-zA-Z]", "", log_file_name)+'_'+re.sub(r"[^가-힣]", "", log_file_name)+'_'
eqp_name = free_name.replace('waf','').replace('ids','').replace('통합','').replace('_','').replace('WAF','').replace('IDS','')

if log_file_name.rfind('통합') > 0 :
    result_csv_file = eqp_name+'_통합_'+'top_20[data_'+str(data_number)+'].csv'
elif log_file_name.rfind('WAF') > 0 or log_file_name.rfind('waf') > 0 :
    result_csv_file = eqp_name+'_WAF_'+'top_20[data_'+str(data_number)+'].csv'
elif log_file_name.rfind('IDS') > 0 or log_file_name.rfind('ids') > 0 :
    result_csv_file = eqp_name+'_IDS_'+'top_20[data_'+str(data_number)+'].csv'
else :
    result_csv_file = eqp_name +'차트데이터용_top_20_분석[data_'+str(data_number)+'].csv'

# 분석 결과를 CSV 파일로 저장
total.to_csv('./../'+result_csv_file, header=True, encoding='utf-8-sig', index=True)



