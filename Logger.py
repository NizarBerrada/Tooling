from config import LOGFILE

class Logger:
    def __init__(self, print_logs: bool = False):
        self.print_logs = print_logs
        self.logfile = LOGFILE 
  
    def alert(self, message: str):
        with open(LOGFILE, "a") as f:
            f.write(message + "\n")
        if self.print_logs:
            print(message)

    def log_suspicious_domains(self, score: float, domain: str, issuer: str):
        # Determiner le niveau de criticite en fonction du score
        criticality = "[HIGH]" if score <= 0 else "[LOW]"

        # Creaation du messager de LOG avec un format specifique
        log_line = f"{criticality} {domain} ( Criticality Score: {score} )    (CA: {issuer} )"
        # Call the alert function to log or print the message
        self.alert(log_line)