# Limpeza e Suporte do Windows

## Descrição

O **Limpeza e Suporte do Windows** é uma ferramenta desenvolvida em PowerShell para auxiliar na manutenção, otimização e suporte técnico de sistemas operacionais Windows. Com uma interface gráfica amigável, o programa oferece uma série de funcionalidades para melhorar o desempenho do sistema, corrigir problemas comuns e gerenciar configurações importantes. Ele é ideal para técnicos de TI, administradores de sistemas e usuários avançados que desejam realizar tarefas de suporte de forma eficiente.

O programa exibe informações do sistema, como nome e IP do computador, e permite ao usuário selecionar múltiplas ações de manutenção através de uma lista de verificação ou executar ações rápidas via um menu de "Mais Ações".

## Funcionalidades

### Informações do Sistema
- Exibe o nome do computador e o endereço IP atual na interface principal.

### Ações de Manutenção (Lista de Verificação)
O usuário pode selecionar várias opções da lista e executá-las clicando no botão "INICIAR". As ações disponíveis incluem:
- **Ativar modo desempenho**: Configura o sistema para priorizar desempenho.
- **Ativar visualizador de fotos do Windows**: Reativa o visualizador de fotos clássico do Windows.
- **Desabilitar Cortana**: Desativa a assistente virtual Cortana.
- **Desativar hibernação**: Desabilita o modo de hibernação para liberar espaço em disco.
- **Gerenciar programas de inicialização**: Permite ativar/desativar programas que iniciam com o sistema.
- **Gerenciar espaço em disco**: Exibe o uso de disco e permite limpar arquivos grandes ou antigos.
- **Limpeza de Disco**: Remove arquivos temporários e desnecessários.
- **Limpeza no Registro**: Remove entradas inválidas do registro do Windows.
- **Otimizar serviços do Windows**: Permite desativar serviços desnecessários para melhorar o desempenho.
- **Verificar integridade do sistema**: Executa `sfc /scannow` e `DISM /Online /Cleanup-Image /RestoreHealth` para reparar arquivos do sistema.
- **Limpar cache DNS**: Executa `ipconfig /flushdns` para resolver problemas de conectividade.

### Ações Rápidas (Menu "Mais Ações")
Através do botão "Mais Ações", o usuário pode executar ações rápidas sem precisar usar a lista de verificação:
- **Alterar nome do computador**: Permite renomear o computador.
- **Recuperar imagem do Windows**: Executa comandos para restaurar a imagem do sistema.
- **Consertar erros do Windows**: Realiza verificações adicionais para corrigir erros do sistema.
- **Iniciar serviços**: Reativa serviços previamente desabilitados.
- **Desativar telemetria**: Desativa configurações de telemetria do Windows para aumentar a privacidade.

### Recursos Adicionais
- **Barra de progresso**: Exibe o progresso das ações selecionadas na lista de verificação.
- **Logs**: Registra todas as ações e erros em um arquivo de log (`C:\Suporte\log.txt`) para auditoria e solução de problemas.
- **Interface temática**: Tema escuro com cores #343434 (fundo), #121212 (botões) e #fff (texto), com efeitos de hover nos botões.

## Requisitos

- **Sistema Operacional**: Windows 10 ou superior.
- **PowerShell**: Versão 5.1 ou superior (padrão no Windows 10/11).
- **Permissões**: Algumas funcionalidades requerem privilégios administrativos. Execute o script como administrador para garantir funcionamento completo.
- **.NET Framework**: 4.5 ou superior (necessário para a interface gráfica Windows Forms).

## Instruções de Uso

1. **Executar o Script**:
   - Certifique-se de que o script PowerShell (`SuporteWindows.ps1`) e o arquivo `Rodar.bat` estão na mesma pasta.
   - Dê um duplo clique no arquivo `Rodar.bat`. Ele iniciará o programa automaticamente no PowerShell com privilégios administrativos.
   - Caso prefira executar manualmente, abra o PowerShell como administrador e execute o comando:
     ```
     .\SuporteWindows.ps1
     ```

2. **Interface Principal**:
   - A janela principal exibe o nome e o IP do computador no lado esquerdo.
   - No lado direito, há uma lista de verificação com várias opções de manutenção.
   - Abaixo da lista, há botões para "INICIAR" as ações selecionadas e "FECHAR" o programa.

3. **Executar Ações de Manutenção**:
   - Marque as opções desejadas na lista de verificação.
   - Clique em "INICIAR" para executar todas as ações selecionadas.
   - Acompanhe o progresso pela barra de progresso e o status pelo log na parte inferior da janela.

4. **Usar o Menu "Mais Ações"**:
   - Clique no botão "MAIS AÇÕES" no lado esquerdo da janela.
   - Uma nova janela será aberta com botões para ações rápidas.
   - Clique no botão desejado (ex.: "ALTERAR NOME", "DESATIVAR TELEMETRIA") para executar a ação.
   - O status da ação será exibido na parte inferior da janela.

5. **Verificar Logs**:
   - Todas as ações e erros são registrados em `C:\Suporte\log.txt`.
   - Abra o arquivo para revisar o histórico de operações.

## Notas de Implementação

- **Segurança**: Algumas ações (como desativar serviços ou alterar o registro) podem impactar o funcionamento do sistema. Sempre revise as opções selecionadas e faça backup de dados importantes antes de executar o script.
- **Customização**: O script pode ser facilmente expandido com novas funcionalidades. Adicione novas funções em `main_form` e inclua-as na lista de verificação (`add_function_list`) ou no menu "Mais Ações" (`Show_More_Actions`).
- **Interface**: A interface foi projetada para ser intuitiva, com um tema escuro que reduz a fadiga visual. Todos os botões possuem efeitos de hover para melhor usabilidade.

## Contribuições

Este é um projeto de código aberto. Para contribuir:
1. Faça um fork do repositório (se disponível).
2. Adicione novas funcionalidades ou corrija bugs.
3. Envie um pull request com uma descrição detalhada das alterações.

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes (se aplicável).

## Contato

Para sugestões, relatórios de bugs ou suporte, entre em contato com o desenvolvedor:
- **Nome**: Julio Barros
- **E-mail**: juliocbarros339@gmail.com

---

**Última Atualização**: 30 de abril de 2025