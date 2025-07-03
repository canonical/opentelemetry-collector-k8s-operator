variable "app_name" {
  description = "Application name"
  type        = string
}

variable "channel" {
  description = "Charm channel"
  type        = string
  default     = "latest/stable"
}

variable "config" {
  description = "Config options as in the ones we pass in juju config"
  type        = map(string)
  default     = {}
}

# We use constraints to set AntiAffinity in K8s
# https://discourse.charmhub.io/t/pod-priority-and-affinity-in-juju-charms/4091/13
variable "constraints" {
  description = "Constraints to be applied"
  type        = string
  # FIXME: Passing an empty constraints value to the Juju Terraform provider currently
  # causes the operation to fail due to https://github.com/juju/terraform-provider-juju/issues/344
  default = "arch=amd64"
}

variable "model" {
  description = "Model name"
  type        = string
}

variable "revision" {
  description = "Charm revision"
  type        = number
  nullable    = true
  default     = null
}

variable "storage_directives" {
  description = "Map of storage used by the application, which defaults to 1 GB, allocated by Juju"
  type        = map(string)
  default     = {}
}

variable "units" {
  description = "Number of units"
  type        = number
  default     = 1
}
