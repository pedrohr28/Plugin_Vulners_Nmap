import sys
import json
import pandas as pd
import re
import psutil
import os
import time
from operator import itemgetter


new_data = []

def processar(vulnerabilidades,metricas_parse,base_dados):
    resultados = []
    #Percorrer as vulnerabilidades encontradas
    for vulnerabilidade in vulnerabilidades:
        #Encontrar a vulnerabilidade na base de dados
        cve_id = re.findall(r'CVE.\d{4}.\d+',vulnerabilidade['id'])
        if cve_id:
            cve_spec  = base_dados[base_dados['cve'] == cve_id[0]]
            if len(cve_spec.iloc[:]) > 0:
                average_score = sum_score = count_score = 0.00
                coluna_econtrada = ''
                #Percorrer as métricas/caracteristicas inseridas pelo usuário
                for metrica in metricas_parse:
                    if len(metrica) >= 4 and metrica[0] in cve_spec.columns:                          
                                nova_metrica = cve_spec[metrica[0]]
                                for line in nova_metrica:
                                    #verificação dos valores numericos
                                    if isinstance(line, int) or isinstance(line, float):
                                        divisao = abs(float(metrica[3]) - float(metrica[2]))
                                        if divisao != 0:
                                            #Calculo da normalização
                                            #somas das normalizações
                                            sum_score = sum_score + (float( ( float(line) - float(metrica[2]) ) / divisao )*(float(metrica[1])))
                                            #soma dos pesos
                                            count_score = count_score + float(metrica[1]) 
                                            coluna_econtrada = 'X' 
                if coluna_econtrada == 'X':                    
                    if count_score != 0:
                        #Calculo da nova pontuação  
                        average_score = (sum_score/count_score)*100
                        average_score = round(average_score,1)
                        #Atribuição da nova pontução ao cvss
                        vulnerabilidade['cvss'] = average_score
        resultados.append(vulnerabilidade)
    return resultados
    
    
#Convertendo vulnerabilidades encontradas em string    
json_string = sys.argv[1]
dados = json.loads(json_string)
process = psutil.Process(os.getpid())
cpu_start = process.cpu_times()
cpu_percent_before = process.cpu_percent(interval=None)
if len(sys.argv) > 1:
    #Caracterisiticas/metricas
    metricas = sys.argv[2]
    metricas_parse = []
    #Dividindo as metricas/caracterisiticas e pesos em lista diferentes
    metricas_nova = metricas.split(":")
    for metrica in metricas_nova:
        cast = str(metrica)
        var_split = cast.split("-")
        if len(var_split) == 2: #somente parametros de pares ... ex: metrica e peso
                metricas_parse.append(var_split)

    #Diretorio do arquivo
    local = str(sys.argv[0])
    tam = len(local)
    remover_python_string = ''
    
    for i in range(tam - 1):
        if local[tam - 1 - i] != '/':
            remover_python_string += local[tam - 1 - i]
        else:
            break
  
    remover_python_string = ''.join(reversed(remover_python_string))
    local_data = local.replace(remover_python_string, '')

    #mapeando diretorio da base de dados
    local_data = local_data + 'vrex.csv'     
            
    if isinstance(dados, list):
        base_dados = pd.read_csv(local_data)
        #Encontrando o max e min das métricas na base de dados
        for metrica in metricas_parse:
            colunas = []
            if len(metrica) >= 2:
                if metrica[0] in base_dados.columns: 
                    for caract in base_dados[metrica[0]]:
                        colunas.append(float(caract))
                    #Valor min da caracteristica
                    metrica.append(float(min(colunas)))
                    #Valor max da caracteristica
                    metrica.append(float(max(colunas)))
        #Recalculo da Vulnerabilidades            
        new_data = processar(dados,metricas_parse,base_dados)
        #Ordenação na forma descrecentes 
        new_data = sorted(new_data, key=itemgetter('cvss'),reverse=True)
else:
    for i in dados:
        new_data.append(i)

#Calculo Final memoria, tempo
memory = process.memory_info().rss / 1024 ** 2
cpu_percent_after = process.cpu_percent(interval=None)
cpu_end = process.cpu_times()
tempo_execucao = cpu_end.user  - cpu_start.user
tempo_execucao_user  = ( cpu_end.user  - cpu_start.user ) 
tempo_execucao_kernel= ( cpu_end.system - cpu_start.system) 
tempo_execucao_cpu   = tempo_execucao_user + tempo_execucao_kernel
for dados in new_data:
    dados['time'] =  round(tempo_execucao_user,0)
    dados['process_usage'] = cpu_percent_after - cpu_percent_before
    dados['usage_memory']  = memory 
    dados['number_vuln']   = len(new_data)
    break
# Retorna a string JSON para o Lua
print(json.dumps(new_data))

sys.stdout.flush()
