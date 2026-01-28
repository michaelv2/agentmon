"""Device-to-policy mapping and lookup."""

from typing import Optional

from agentmon.policies.models import Device, ParentalPolicy


class DeviceManager:
    """Manages device-to-policy mappings for quick lookup.

    Provides O(1) lookup from client IP to device and policy.
    """

    def __init__(
        self,
        devices: list[Device],
        policies: dict[str, ParentalPolicy],
    ) -> None:
        """Initialize device manager.

        Args:
            devices: List of device configurations
            policies: Dictionary mapping policy names to policy objects
        """
        self._ip_to_device: dict[str, Device] = {}
        self._policies = policies

        # Build IP lookup table
        for device in devices:
            for ip in device.client_ips:
                self._ip_to_device[ip] = device

    def get_device(self, client_ip: str) -> Optional[Device]:
        """Look up device by client IP.

        Args:
            client_ip: IP address of the client

        Returns:
            Device if found, None otherwise
        """
        return self._ip_to_device.get(client_ip)

    def get_policy(self, client_ip: str) -> Optional[tuple[Device, ParentalPolicy]]:
        """Look up device and policy by client IP.

        Args:
            client_ip: IP address of the client

        Returns:
            Tuple of (Device, ParentalPolicy) if found, None otherwise
        """
        device = self._ip_to_device.get(client_ip)
        if not device:
            return None

        policy = self._policies.get(device.policy_name)
        if not policy:
            return None

        return (device, policy)

    def get_all_devices(self) -> list[Device]:
        """Return all configured devices."""
        # Deduplicate since multiple IPs can map to same device
        seen = set()
        devices = []
        for device in self._ip_to_device.values():
            if device.name not in seen:
                seen.add(device.name)
                devices.append(device)
        return devices

    def get_all_policies(self) -> list[ParentalPolicy]:
        """Return all configured policies."""
        return list(self._policies.values())
