from utils.requester import get
from core.finding import Finding

class WixBookingLeakScanner:
    name = "wix_booking_leak"

    def run(self, target):
        r = get(f"{target}/_api/wix-bookings-server-webapp/v1/availability")
        if r and "staffId" in r.text:
            f = Finding(
                module=self.name,
                title="Wix Booking Staff Information Leak",
                severity="low",
                description="The booking system API is exposing internal staff identifiers or schedules.",
                endpoint=target,
                evidence=r.text
            )
            return [f.to_dict()]
        return None