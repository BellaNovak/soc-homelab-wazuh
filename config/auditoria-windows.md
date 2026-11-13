# Auditoria do Windows (win-alvo)

O Windows vem com boa parte da auditoria de segurança desligada. Sem estes comandos, vários eventos do lab nem chegam a ser gravados. Rodei no PowerShell como administrador:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
net accounts /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:15
```

| Configuração | Eventos que gera no lab | Cenários |
|---|---|---|
| Logon | 4625 (falha de logon) | 1 |
| User Account Management | 4720 (conta criada), 4722 (conta habilitada), 4738 (conta alterada), 4740 (conta bloqueada) | 1 e 3 |
| Security Group Management | 4732 (membro adicionado a grupo), 4733 (membro removido) | 3 |
| Other Object Access Events | 4698 (tarefa agendada criada) | 6 |
| net accounts | Bloqueia a conta depois de 5 senhas erradas em 15 minutos, por 15 minutos | 1 |

Os outros eventos do lab não dependem destas configurações: o 1102 (log apagado) é sempre gravado, e o 7045 (serviço novo) vai para o log System.