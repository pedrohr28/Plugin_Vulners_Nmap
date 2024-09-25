# Plugin_Vulners_Nmap
# Intalação completa para o funcionamento do PluginVulners no Sistema operacional Kali Linux
## Instalar o Nmap
- sudo apt update
- sudo apt upgrade
- sudo apt install nmap
## Para o funcionamento correto é necessário a instalação do Vulners pelo link do github abaixo:
- https://github.com/vulnersCom/nmap-vulners
## Após a instalação do Vulners é necessário as instalações das bibliotecas/dependências a seguir:
- Python: Pandas, Psutil, Json e Time
- Lua: Json, Socket e Http
## Após a instalação do Vulners, Python e das bibliotecas listadas acima, é necessário substituir o arquivo original vulners.nse pelo vulners.nse disponibilizado neste GitHub.
- Exemplo do local onde fica localizado o arquivo no kali Linux: /usr/share/nmap/scripts/
##  Após a substituição do arquivo original:
- Copie o arquivo PluginVulners.py deste repositório para um diretório local e insira o arquivo da base de dados nesse mesmo diretório.
- O arquivo da base de dados deve ter o nome vrex.csv, esse arquvio está contido nesse repositório github, compactado como arquivo .zip.
## Exemplo de sintaxe para a execução do Vulners configurado com o PluginVulners:
- nmap --script=vulners --script-args metrics=<carcteristica1-peso1:carcteristica2-peso2>, diretory=<diretorio_modulo> <ip_maquina_target>
## Exemplo sintaxe do argumento metrics:
- metrics=lbl_exploits_delta_days-10:delta_days_patch-2
## Exemplo sintaxe do argumento diretory onde está localilzado o plugin PluginVulners:
- diretory=/home/kali/Desktop/Plugin_Vulners_Nmap/PluginVulners.py
## É necessário a ativação do argumento pelo comando:
- --script-args
## Exemplo sintaxe completa da execução do PluginVulners:
- nmap --script=vulners --script-args metrics=lbl_exploits_delta_days-10:lbl_exploits_weaponized_count-10:lbl_exploits_has-10:lbl_exploits_verified-10:delta_days_oval-2:delta_days_patch-2:delta_days_proposed-2,diretory=/home/kali/Desktop/Plugin_Vulners_Nmap/PluginVulners.py 192.168.1.9
