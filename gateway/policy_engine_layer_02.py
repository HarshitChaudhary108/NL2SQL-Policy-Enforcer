import yaml
from pathlib import Path

class GATEWAY_LAYER:
    def __init__(self, policy_dir: str = "policy/roles"):
        self.policies = {}
        self._load_all_policies(policy_dir)

    def _load_all_policies(self, policy_dir: str):
        for yaml_file in Path(policy_dir).glob("*.yml"):
            with open(yaml_file, "r") as file:
                policy = yaml.safe_load(file)
                self.policies[policy["role"]] = policy

    def evaluate(self, command, tables, role:str="analyst", tool_name:str = "sql"):
        policy = self.policies.get(role)
        if not policy:
            return {"permitted": False, "reason": f"Unknown Role: {role}"}

        #check tool_permission
        if tool_name not in policy["allowed_tools"]:
            return {"permitted": False, "reason": f"Tool '{tool_name}' not allowed for role '{role}'"}

        #check command_permission
        if tool_name == "sql":
                allowed_ops = [op.upper() for op in policy["tools"]["sql"]["allowed_operations"]]
                blocked_patterns = [p.upper() for p in policy["tools"]["sql"]["blocked_patterns"]]

                for comm in command:
                    comm_upper = comm.upper()
                    if comm_upper in blocked_patterns:
                        return {"permitted": False, "reason": f"Command '{comm}' is explicitly blocked for role '{role}'"}
                    if comm_upper not in allowed_ops:
                        return {"permitted": False, "reason": f"Command '{comm}' not in allowed operations for role '{role}'"}

                for table in tables:
                    if table not in policy["tools"]["sql"]["allowed_tables"] and policy["tools"]["sql"]["blocked_tables"]:
                        return {"permitted": False, "reason": f"Table '{table}' does not exists"}

                    if table in policy["tools"]["sql"]["blocked_tables"]:
                        return {"permitted": False, "reason": f"Table '{table}' is explicitly blocked for role '{role}'"}

                    if table not in policy["tools"]["sql"]["allowed_tables"]:
                        return {"permitted": False, "reason": f"Table '{table}' not permitted for role '{role}'"}
        
        return {"permitted": True, "reason": "Policy check passed"}

        