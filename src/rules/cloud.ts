import { flags } from "../analyze.js";
import type { CommandRule } from "./types.js";

export const infraDestroy: CommandRule = {
  kind: "command",
  id: "cloud.infra-destroy",
  decision: "ask",
  description: "Tearing down infrastructure (terraform/pulumi/cdk destroy, serverless remove)",
  check(cmd) {
    const p = cmd.program;
    const a = cmd.args;
    if (["terraform", "tofu", "terragrunt"].includes(p) && (a[0] === "destroy" || (a[0] === "apply" && a.includes("-destroy")))) {
      return { reason: `\`${p} ${a[0]}\` deletes every resource in this configuration.`, suggestion: `Run \`${p} plan -destroy\` first and review it.` };
    }
    if ((p === "pulumi" || p === "cdk") && a[0] === "destroy") return { reason: `\`${p} destroy\` deletes the stack's cloud resources.` };
    if ((p === "npx" || p === "pnpx") && a[0] === "cdk" && a[1] === "destroy") return { reason: "`cdk destroy` deletes the stack's cloud resources." };
    if ((p === "serverless" || p === "sls") && a[0] === "remove") return { reason: `\`${p} remove\` deletes the deployed service.` };
    return null;
  },
  examples: {
    flag: ["terraform destroy -auto-approve", "terraform apply -destroy", "pulumi destroy --yes", "npx cdk destroy MyStack", "sls remove --stage prod"],
    pass: ["terraform plan", "terraform apply", "pulumi up"],
  },
};

const KUBE_BROAD = new Set(["namespace", "namespaces", "ns", "node", "nodes", "pv", "persistentvolume", "persistentvolumes", "crd", "crds", "customresourcedefinition", "customresourcedefinitions", "clusterrole", "clusterrolebinding"]);

export const kubeDelete: CommandRule = {
  kind: "command",
  id: "cloud.kubectl-delete",
  decision: "ask",
  description: "Broad Kubernetes deletes (namespaces, nodes, --all) and helm uninstall",
  check(cmd) {
    if (cmd.program === "helm" && (cmd.args[0] === "uninstall" || cmd.args[0] === "delete")) {
      return { reason: `\`helm ${cmd.args[0]}\` removes a release and its resources.` };
    }
    if (cmd.program !== "kubectl" && cmd.program !== "oc") return null;
    const idx = cmd.args.indexOf("delete");
    if (idx === -1) return null;
    const rest = cmd.args.slice(idx + 1);
    const f = flags(rest);
    const kind = rest.find((r) => !r.startsWith("-"))?.split("/")[0]?.toLowerCase() ?? "";
    if (f.long.has("--all") || f.long.has("--all-namespaces") || f.short.has("A")) {
      return { reason: "`kubectl delete --all` removes every matching resource." };
    }
    if (KUBE_BROAD.has(kind)) return { reason: `Deleting a ${kind} removes everything that depends on it.` };
    return null;
  },
  examples: {
    flag: ["kubectl delete namespace staging", "kubectl delete pods --all", "kubectl -n prod delete ns/prod", "helm uninstall api"],
    pass: ["kubectl delete pod api-7d9f", "kubectl get pods -A", "helm upgrade api ./chart"],
  },
};

export const cloudDelete: CommandRule = {
  kind: "command",
  id: "cloud.resource-delete",
  decision: "ask",
  description: "Deleting cloud resources via aws, gcloud, az, gsutil, doctl, heroku, fly, vercel",
  check(cmd) {
    const p = cmd.program;
    const a = cmd.args;
    if (p === "aws") {
      if (a[0] === "s3" && (a[1] === "rb" || (a[1] === "rm" && a.includes("--recursive")))) {
        return { reason: `\`aws s3 ${a[1]}\` deletes S3 objects${a[1] === "rb" ? " and the bucket" : " recursively"}.` };
      }
      const op = a.find((x) => /^(delete|terminate|remove|deregister|purge)-/.test(x));
      if (op) return { reason: `\`aws ... ${op}\` deletes cloud resources.` };
    }
    if ((p === "gcloud" || p === "az" || p === "doctl") && a.includes("delete")) {
      return { reason: `\`${p} ... delete\` deletes cloud resources.` };
    }
    if (p === "gsutil" && (a[0] === "rb" || (a[0] === "rm" && (a.includes("-r") || a.includes("-R"))))) {
      return { reason: "`gsutil` would delete a bucket or objects recursively." };
    }
    if (p === "heroku" && a.some((x) => ["apps:destroy", "pg:reset", "apps:delete"].includes(x))) {
      return { reason: "This Heroku command deletes an app or database." };
    }
    if ((p === "fly" || p === "flyctl") && ((a[0] === "apps" && a[1] === "destroy") || a[0] === "destroy")) {
      return { reason: "`fly apps destroy` deletes the app." };
    }
    if (p === "vercel" && (a[0] === "remove" || a[0] === "rm")) return { reason: "`vercel remove` deletes deployments or a project." };
    return null;
  },
  examples: {
    flag: ["aws s3 rm s3://bucket --recursive", "aws s3 rb s3://bucket --force", "aws ec2 terminate-instances --instance-ids i-123", "aws rds delete-db-instance --db-instance-identifier prod", "gcloud projects delete my-proj", "az group delete -n rg", "heroku apps:destroy myapp"],
    pass: ["aws s3 ls", "aws s3 cp file s3://bucket/", "gcloud compute instances list", "aws ec2 describe-instances"],
  },
};

export const dockerPrune: CommandRule = {
  kind: "command",
  id: "cloud.docker-volumes",
  decision: "ask",
  description: "Deleting Docker volumes (system prune --volumes, volume rm/prune, compose down -v)",
  check(cmd) {
    if (cmd.program !== "docker" && cmd.program !== "podman" && cmd.program !== "docker-compose") return null;
    const a = cmd.args;
    if (a[0] === "system" && a[1] === "prune" && (a.includes("--volumes") || a.includes("-a") || a.includes("--all"))) {
      return { reason: "`docker system prune` with these flags deletes all unused images and possibly volumes." };
    }
    if (a[0] === "volume" && (a[1] === "rm" || a[1] === "prune")) return { reason: `\`docker volume ${a[1]}\` deletes volume data such as local databases.` };
    const down = cmd.program === "docker-compose" ? a[0] === "down" : a[0] === "compose" && a.includes("down");
    if (down && (a.includes("-v") || a.includes("--volumes"))) {
      return { reason: "`docker compose down -v` deletes the project's volumes, including database data.", suggestion: "Use `docker compose down` without `-v` to keep data." };
    }
    return null;
  },
  examples: {
    flag: ["docker system prune -a --volumes", "docker volume rm pgdata", "docker compose down -v", "docker-compose down --volumes"],
    pass: ["docker compose down", "docker system prune", "docker build -t app ."],
  },
};

export const cloudRules = [infraDestroy, kubeDelete, cloudDelete, dockerPrune];
