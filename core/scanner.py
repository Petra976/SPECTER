# core/scanner.py

class Scanner:
    def __init__(self, target):
        self.target = target
        self.shared_data = {
            "discovered_endpoints": None,
            "idor_results": None
        }

    def run_module(self, module_class):
        module = module_class()

        if hasattr(module, "requires"):
            if "endpoints" in module.requires:
                if not self.shared_data["discovered_endpoints"]:
                    return None
                return module.run(self.target, self.shared_data["discovered_endpoints"])

            if "idor" in module.requires:
                if not self.shared_data["idor_results"]:
                    return None
                return module.run(self.shared_data["idor_results"])

        result = module.run(self.target)
        if module.__class__.__name__ == "WixPublicAPIScanner":
            self.shared_data["discovered_endpoints"] = result.get("exposed_endpoints", [])

        if module.__class__.__name__ == "WixIDORDetector":
            self.shared_data["idor_results"] = result

        return result
