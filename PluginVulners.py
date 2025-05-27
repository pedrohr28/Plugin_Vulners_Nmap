import sys
import json
import pandas as pd
import re
import psutil
import os
from operator import itemgetter


def extrair_cve_id(vuln_id):
    match = re.findall(r'CVE.\d{4}.\d+', vuln_id)
    return match[0] if match else None


def calcular_score_normalizado(cve_spec, metricas_parse):
    soma_score = 0.0
    soma_pesos = 0.0
    metrica_encontrada = False

    for metrica in metricas_parse:
        if len(metrica) < 4 or metrica[0] not in cve_spec.columns:
            continue

        valores_coluna = cve_spec[metrica[0]]
        peso = float(metrica[1])
        min_val = float(metrica[2])
        max_val = float(metrica[3])
        intervalo = abs(max_val - min_val)

        if intervalo == 0:
            continue

        for valor in valores_coluna:
            if isinstance(valor, (int, float)):
                normalizado = (float(valor) - min_val) / intervalo
                soma_score += normalizado * peso
                soma_pesos += peso
                metrica_encontrada = True

    if metrica_encontrada and soma_pesos > 0:
        score = round((soma_score / soma_pesos) * 100, 1)
        return score
    return None


def processar_vulnerabilidades(vulnerabilidades, metricas_parse, base_dados):
    resultados = []

    for vuln in vulnerabilidades:
        cve_id = extrair_cve_id(vuln['id'])
        if cve_id:
            cve_spec = base_dados[base_dados['cve'] == cve_id]
            if not cve_spec.empty:
                novo_score = calcular_score_normalizado(cve_spec, metricas_parse)
                if novo_score is not None:
                    vuln['cvss'] = novo_score
        resultados.append(vuln)

    return resultados


def obter_diretorio_base(script_path):
    return os.path.dirname(os.path.abspath(script_path)) + '/'


def carregar_metricas(argumento_metricas):
    metricas_parse = []
    for metrica in argumento_metricas.split(":"):
        partes = metrica.split("-")
        if len(partes) == 2:
            metricas_parse.append(partes)
    return metricas_parse


def atualizar_com_min_max(metricas_parse, base_dados):
    for metrica in metricas_parse:
        if len(metrica) >= 2 and metrica[0] in base_dados.columns:
            valores = pd.to_numeric(base_dados[metrica[0]], errors='coerce').dropna()
            if not valores.empty:
                metrica.append(float(valores.min()))
                metrica.append(float(valores.max()))
    return metricas_parse


def calcular_recursos(cpu_start, cpu_end, process, cpu_percent_before):
    memoria_mb = process.memory_info().rss / 1024 ** 2
    cpu_percent_after = process.cpu_percent(interval=None)
    tempo_user = cpu_end.user - cpu_start.user
    tempo_kernel = cpu_end.system - cpu_start.system
    return {
        'tempo_user': round(tempo_user, 0),
        'uso_processador': cpu_percent_after - cpu_percent_before,
        'memoria_usada': memoria_mb,
        'total_vulnerabilidades': None  # será adicionado depois
    }


def main():
    json_string = sys.argv[1]
    vulnerabilidades = json.loads(json_string)

    process = psutil.Process(os.getpid())
    cpu_start = process.cpu_times()
    cpu_percent_before = process.cpu_percent(interval=None)

    if len(sys.argv) > 2:
        metricas_parse = carregar_metricas(sys.argv[2])
        caminho_base = obter_diretorio_base(sys.argv[0]) + 'vrex.csv'
        base_dados = pd.read_csv(caminho_base)

        metricas_parse = atualizar_com_min_max(metricas_parse, base_dados)
        new_data = processar_vulnerabilidades(vulnerabilidades, metricas_parse, base_dados)
        new_data.sort(key=itemgetter('cvss'), reverse=True)
    else:
        new_data = vulnerabilidades.copy()

    cpu_end = process.cpu_times()
    recursos = calcular_recursos(cpu_start, cpu_end, process, cpu_percent_before)
    recursos['total_vulnerabilidades'] = len(new_data)

    # Atualiza apenas o primeiro elemento com informações do processo
    if new_data:
        new_data[0].update({
            'time': recursos['tempo_user'],
            'process_usage': recursos['uso_processador'],
            'usage_memory': recursos['memoria_usada'],
            'number_vuln': recursos['total_vulnerabilidades']
        })

    print(json.dumps(new_data))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
