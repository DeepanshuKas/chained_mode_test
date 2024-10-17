{
    addNs(labels)::
        if labels == '' then
            {}
        else
            {
                'labels': std.parseJson(labels)
            }
}
