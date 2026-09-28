from forensic_engine.forensic_parser import parse_all_results


print("======================================")
print("FORENSIRANSOM AI")
print("FORENSIC PARSER TEST")
print("======================================")


events = parse_all_results()


print("\nTotal forensic events:", len(events))


for index, event in enumerate(events[:30], start=1):

    print("\n------------------------------")
    print("Event:", index)
    print("Type:", event["event_type"])
    print("Source:", event["source"])
    print("Data:", event["raw_data"])


print("\n======================================")
print("PARSER TEST COMPLETED")
print("======================================")