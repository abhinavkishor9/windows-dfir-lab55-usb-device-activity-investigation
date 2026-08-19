A Windows endpoint has been flagged for possible removable-media usage during routine forensic review.

No confirmed USB insertion event is available, and the commonly referenced USBSTOR Registry location is not present on the system. The analyst therefore cannot rely on a single artifact to determine whether a removable device was used.

The investigation begins by examining the device information that Windows has retained, followed by storage mappings, system activity, logged-on users, process execution, network connections, and recently modified files.

The analyst then correlates these artifacts by timestamp to determine whether they form a consistent sequence of activity involving a removable device.

The investigation aims to establish:

Whether Windows has recorded USB-related device information.
Whether the available evidence indicates a removable device was connected.
Whether the activity can be associated with an interactive user.
Whether relevant processes or file activity occurred during the same timeframe.
Whether there is sufficient evidence to support removable-media data transfer.

The investigation will distinguish between device presence, device connection, user activity, and data transfer, rather than treating any single artifact as conclusive proof.
